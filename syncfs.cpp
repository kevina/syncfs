/*
  Z-Backup File System
  Copyright (C) 2015 Kevin Atkinson
  
  Based on the Big Brother File System
  Copyright (C) 2012 Joseph J. Pfeiffer, Jr., Ph.D. <pfeiffer@cs.nmsu.edu>

  This program can be distributed under the terms of the GNU GPLv3.
  See the file COPYING.

  This code is derived from function prototypes found /usr/include/fuse/fuse.h
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>
  His code is licensed under the LGPLv2.
  A copy of that code is included in the file fuse.h
*/

#include "params.h"
#include "remote.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <fuse.h>
#include <libgen.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <signal.h>

#include <stdarg.h>
#include <assert.h>

#include <string>
#include <vector>
#include <utility>
#include <limits>

using std::string;
using std::vector;

#ifdef NDEBUG
// CMake can enable NDEBUG, something that is rarely done in the Unix
// world.  I am not alone in considering -DNDEBUG to be EBW =
// (Evil, Bad, and Wrong).  See
// https://lists.debian.org/debian-devel/2013/02/msg00351.html This
// check is to guard against that.
#error NDEBUG builds are unsupported
#endif

#include "sqlite3.hpp"
#include "json.hpp"

typedef int64_t FileId;
typedef int64_t ContentId;
enum OpenState {Closed, OpenedRO, OpenedRW};
#include "queries-gen.hpp"


//////////////////////////////////////////////////////////////////////////////
//
// Global state
//

#define SCHEMA_VERSION "3"

static const char * rootdir = NULL;
FILE * logfile = NULL;
RemoteState remote_state;
//RemoteOps remote = file_remote;
RemoteOps remote = drive_remote;
bool LOG_SQL = false;

//////////////////////////////////////////////////////////////////////////////
//
// Database State and Mutex
//

pthread_mutex_t db_mutex = PTHREAD_ERRORCHECK_MUTEX_INITIALIZER_NP;
sqlite3 * db = NULL;
std::vector<SqlStmtBase *> sql_stmts;

// FileID == -1 if local, < -1 if proc file
std::vector<FileId> opened_files;
std::vector<const char *> proc_file_content;
#define PENDING_MAX_SIZE (2*1024)
#define PENDING_FH_START 4000000000u

struct ScopedMutex {
  pthread_mutex_t * mutex;
  bool locked;
  ScopedMutex(pthread_mutex_t * m, bool start_locked = true) : mutex(m), locked(false) {if (start_locked) lock();}
  ScopedMutex(ScopedMutex && other) : mutex(other.mutex), locked(other.locked) {other.mutex = NULL;}
  ScopedMutex & operator=(ScopedMutex & other) = delete;
  ~ScopedMutex() {if (mutex) unlock();}
  //void unlock() {if (locked && mutex == &db_mutex) db_locked = false; if (locked) pthread_mutex_unlock(mutex); locked = false; }
  //void lock() {if (!locked) pthread_mutex_lock(mutex); locked = true; if (mutex == &db_mutex) db_locked = true; }
  void unlock() {if (locked) pthread_mutex_unlock(mutex); locked = false; }
  void lock() {if (!locked) pthread_mutex_lock(mutex); locked = true; }
  void yield () {assert(locked); unlock(); lock(); }

};
struct DbMutex : public ScopedMutex {
  DbMutex(bool start_locked = true) : ScopedMutex(&db_mutex, start_locked) {}
};
bool exiting = false;

class Worker {
public:
  const char * worker_name;
  pthread_t thread;
  pthread_cond_t cond;
  void * start();
  void notify() {
    assert(db_locked);
    more_to_do_now = true;
    if (!waiting) return;
    pthread_cond_signal(&cond);
    waiting = false;
  }
protected:
  bool waiting;
  bool more_to_do_now;
  int more_to_do;
  int error_backoff;
  virtual bool do_work(DbMutex &lock) = 0; // returns true if the function should
			                    // be called again without waiting
  Worker(const char * name) 
    : worker_name(name), cond(PTHREAD_COND_INITIALIZER), 
      waiting (false), more_to_do_now(false), more_to_do(), error_backoff() {}

public:
  void create() {
    pthread_create(&thread, NULL, thread_start, this);
  }

  static void * thread_start(void *);
};

// The checksum thread computes checksums for modified files
class LocalPartThread : public Worker {
public:
  LocalPartThread() : Worker("local part thread") {}
protected:
  bool do_work(DbMutex &lock);
} * local_part_thread = NULL;

// The cleanup thread removes files locally that are no longer needed
// and also upload files, giving priority to files that could be
// removed after uploading
class UploaderThread : public Worker {
public:
  UploaderThread() : Worker("uploader thread") {}
protected:
  bool do_work(DbMutex &lock);
} * uploader_thread =  NULL;

// The extra_uploader thread is an optional thread that uploads files
// giving priority to smaller files
class ExtraUploaderThread : public Worker {
public:
  ExtraUploaderThread() : Worker("extra uploader thread") {}
protected:
  bool do_work(DbMutex &lock);
} * extra_uploader_thread =  NULL;

// The metadata thread pushes other changes not handled by other threads
class MetadataThread : public Worker {
public:
  MetadataThread() : Worker("metadata thread") {}
protected:
  bool do_work(DbMutex &lock);
} * metadata_thread = NULL;

void log_msg(const char *format, ...)
  __attribute__ ((format (printf, 1, 2)));

static void check_schema(bool reset_db) {
  FILE * f = NULL;
  f = fopen(".var/schema_version", "r");
  if (reset_db) goto create;
  if (!f && errno == ENOENT) goto create;
  if (!f) goto error;
  {
    char * str;
    size_t sz = 0;
    auto len = getline(&str, &sz, f);
    if (len == -1 && ferror(f)) goto error;
    if (len == 0 || len == -1) goto create;
    if (str[len-1] == '\n') str[len-1] = '\0';
    if (strcmp(str, SCHEMA_VERSION) != 0) {
      fprintf(stderr, "Schema version mismatch (existing: %s, need: %s) please reset the database.\n", str, SCHEMA_VERSION);
      exit (-1);
    }
  }
  /* all good */
  fclose(f);
  return;
 create: {
    if (f) fclose(f);
    FILE * f = fopen(".var/schema_version", "w");
    if (!f) goto error;
    int res = fprintf(f, "%s\n", SCHEMA_VERSION);
    if (res < 0) goto error;
    fclose(f);
    return;
  }
 error: {
    if (f) fclose(f);
    fprintf(stderr, "Problem when reading or writing file: .var/schema_version\n");
    exit (-1);
  }
}


//////////////////////////////////////////////////////////////////////////////
//
// Policy functions
//

#define UPLOAD_WAIT 30
#define REMOVE_WAIT 90
//#define TMP_SIZE_OFFLOAD 128*1024

#define MIN_BACKOFF_ERROR 5
#define MAX_BACKOFF_ERROR 320

struct PathInfo {
  std::string path; // NOTE: A String is an overkill here
  bool prefix_match;
  PathInfo(const char * p) : path(p) {
    prefix_match = path.back() == '/' ? true : false;
  }
};

template <typename T>
struct MatchPath : public std::vector<std::pair<PathInfo,T> > {
  typedef std::vector<std::pair<PathInfo,T> > Base;
  typedef typename Base::const_iterator iterator;
  typedef typename Base::value_type value_type;
  MatchPath() {}
  MatchPath(std::initializer_list<value_type> init)
    : Base(init) {prioritize();}
  MatchPath& operator=(std::initializer_list<typename Base::value_type> init) {
    Base::operator=(init);
    prioritize();
    return *this;
  }
  const T * match(const char * to_match, iterator & i) const {
    while (i != this->end()) {
      auto & key = i->first;
      if (key.prefix_match) {
	if (strncmp(key.path.c_str(), to_match, key.path.size()) == 0)
	  return &(i++)->second;
      } else {
	if (key.path == to_match) 
	  return &(i++)->second;
      }
      ++i;
    }
    return NULL;
  }  
  const T * match(const char * to_match) const {
    iterator i = this->begin();
    return match(to_match, i);
  }
  void prioritize(int skip = 0) {
    auto lt = [](const value_type & a, const value_type & b) -> bool {
      if (a.first.path.size() > b.first.path.size()) return true;
      if (a.first.path.size() < b.first.path.size()) return false;
      return a.first.path < b.first.path;
    };
    std::sort(this->begin() + skip, this->end(), lt);
  }
};

struct LocalOnly {
  MatchPath<bool> data;
  // LocalOnly() {
  //   data = {{"/", false}, {"/.etc/", true},{"/.var/", true}};
  // }
  bool operator()(const char * path) {
    //log_msg("local only?? %s\n", path);
    return *data.match(path);
  }
} local_only;

enum Access {NotAllowed, ReadOnly, CreateOnly, ReadWrite};
struct PathAccess {
  MatchPath<Access> data;
  // PathAccess() {
  //   data = {
  //     {"/", NotAllowed},
  //     {"/info", CreateOnly},
  //     {"/tmp", CreateOnly},     {"/tmp/", ReadWrite},
  //     {"/backups", CreateOnly}, {"/backups/", ReadWrite},
  //     {"/bundles", CreateOnly}, {"/bundles/", CreateOnly},
  //     {"/index", CreateOnly},   {"/index/", CreateOnly},
  //     {"/.var/", ReadOnly}, {"/.etc/", ReadWrite}
  //   };
  // }
  Access operator()(const char * path) const {
    return *data.match(path);
  }
} path_access;

Access dir_access(const char * path) {
  unsigned sz = strlen(path);
  char dir[sz + 2];
  memcpy(dir, path, sz);
  dir[sz] = '/';
  dir[sz+1] = '\0';
  auto i = path_access.data.cbegin();
  auto val = ReadOnly;
  while (auto v = path_access.data.match(dir,i)) {
    if (*v == CreateOnly || *v == ReadWrite) val = ReadWrite;
  }
  return val;
}

#define FOREVER INT_MAX

struct ShouldUpload {
  struct Val {
    int32_t min_wait; // time to wait after the file is closed for writing
    int32_t max_wait; // upload after this time, even if file is less than if_larger_than;
    int64_t keep_size;
  };
  MatchPath<Val> data;
  // ShouldUpload() {
  //   data = {{"/tmp/", {-1,-1,TMP_SIZE_OFFLOAD}},
  //           {"/", {UPLOAD_WAIT, FOREVER, 0}}}; 
  // }
  // should path be uploaded to the server?
  // return -1 if the path should never be upload
  // 0 to upload it now
  // > 0 to possible upload it latter, returns the number of seconds to wait until we should ask again
  // INT_MAX possible to upload latter once conditions change
  int operator()(FileId id, const char * path, time_t atime, time_t mtime, int size, time_t now) const {
    if (local_only(path)) 
      return -1;
    auto i = data.begin();
    Val val = {-1, -1, -1};
    while (auto v = data.match(path, i)) {
      if (val.min_wait == -1 && v->min_wait != -1) val.min_wait = v->min_wait;
      if (val.max_wait == -1 && v->max_wait != -1) val.max_wait = v->max_wait;
      if (val.keep_size == -1 && v->keep_size != -1) val.keep_size = v->keep_size;
    }
    if (val.keep_size != 0) {
      if (now - mtime >= val.max_wait) return 0;
      if (size < val.keep_size) return val.max_wait;
    }
    if (now - mtime < val.min_wait) return val.min_wait;
    return 0;
  }
} should_upload;

struct MayRemove {
  struct Val {
    int32_t wait; // time to wait after the file is last closed
  };
  MatchPath<Val> data;
  // MayRemove() {
  //   data = {{"/tmp/", {REMOVE_WAIT}},
  //           {"/bundles/", {REMOVE_WAIT}},
  //           {"/", {FOREVER}}};
  // }
  // should the local copy of path be removed?
  // returns the same values as upload_path
  int operator()(FileId id, const char * path, time_t atime, time_t mtime, int size, time_t now) const {
    if (local_only(path)) 
      return -1;
    auto i = data.begin();
    Val val = {-1};
    while (auto v = data.match(path, i)) {
      if (val.wait == -1 && v->wait != -1) val.wait = v->wait;
    }
    if (val.wait == FOREVER) return -1;
    if (now - atime < val.wait) return val.wait;
    return 0;
  }
} may_remove;

//////////////////////////////////////////////////////////////////////////////
//
// Misc helper bits
//

void init_db(const char * dir, bool reset_db);
void close_db();

// Report errors to logfile and give -errno to caller
static int syncfs_error(const char *str)
{
  int ret = -errno;
    
  log_msg("    ERROR %s: %s\n", str, strerror(errno));
    
  return ret;
}

static bool path_writable(const char * path) {
  return path_access(path) == ReadWrite;
}

enum AccessMode {READ, MOD_DIR, MOD_FILE};
// FIXME: Make boolean, if false then code should return -EPERM (not EACCESS)
bool access_ok(const char *path, AccessMode mode) 
{
  auto access = path_access(path);
  bool res = true;
  if (access == ReadWrite) {
    /* all okay */
  } else if (access == CreateOnly) {
    if (mode == MOD_FILE) res = false;
  } else if (access == ReadOnly) {
    if (mode != READ) res = false;
  } else {
    res = false;
  }
  if (!res) 
    log_msg("    ERROR %s: %s\n", path, strerror(EPERM));
  return res;
}
#define CHECKPATH(path, mode) if (!access_ok(path, mode)) return -EPERM;

//  All the paths I see are relative to the root of the mounted
//  filesystem.  In order to get to the underlying filesystem, I need to
//  have the mountpoint.  I'll save it away early on in main(), and then
//  whenever I need a path for something I'll call this to construct
//  it.

static void syncfs_fullpath(char fpath[PATH_MAX], const char *path)
{
  strcpy(fpath, rootdir);
  strncat(fpath, path, PATH_MAX); // ridiculously long paths will
  // break here
}

void log_msg(const char *format, ...)
{
  va_list ap;
  va_start(ap, format);

  vfprintf(logfile, format, ap);
}

//////////////////////////////////////////////////////////////////////////////
//
// Fuse functions
//

////////
//
// Operations on directories (that don't access the database)
//

/** Create a directory */
int syncfs_mkdir(const char *path, mode_t mode)
{
  int retstat = 0;
  char fpath[PATH_MAX];

  CHECKPATH(path, MOD_DIR);
    
  log_msg("\nsyncfs_mkdir(path=\"%s\", mode=0%3o)\n",
          path, mode);
  syncfs_fullpath(fpath, path);
    
  retstat = mkdir(fpath, mode);
  if (retstat < 0)
    retstat = syncfs_error("syncfs_mkdir mkdir");
    
  return retstat;
}

/** Remove a directory */
int syncfs_rmdir(const char *path)
{
  int retstat = 0;
  char fpath[PATH_MAX];
    
  CHECKPATH(path, MOD_DIR);

  log_msg("syncfs_rmdir(path=\"%s\")\n",
          path);
  syncfs_fullpath(fpath, path);
    
  retstat = rmdir(fpath);
  if (retstat < 0)
    retstat = syncfs_error("syncfs_rmdir rmdir");
    
  return retstat;
}

//////////
//
// Operations on Open Files.
// (None of which involve accessing the database).
//

/** Read data from an open file */
int pending_read(char *buf, size_t size, off_t offset, struct fuse_file_info *fi);
int syncfs_read(const char *, char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
  int retstat = 0;

  //log_msg("syncfs_read(fh=%lld, size=%d, offset=%lld)\n", fi->fh, size,offset);

  if (fi->fh >= PENDING_FH_START)
    return pending_read(buf,size,offset,fi);
    
  retstat = pread(fi->fh, buf, size, offset);
  if (retstat < 0)
    retstat = syncfs_error("syncfs_read read");
    
  return retstat;
}

/** Write data to an open file */
int syncfs_write(const char *, const char *buf, size_t size, off_t offset,
             struct fuse_file_info *fi)
{
  int retstat = 0;
    
  retstat = pwrite(fi->fh, buf, size, offset);
  if (retstat < 0)
    retstat = syncfs_error("syncfs_write pwrite");
    
  return retstat;
}

/** Change the size of an open file */
int syncfs_ftruncate(const char *, off_t newsize, struct fuse_file_info *fi)
{
  int retstat = 0;
    
  //log_msg("\nsyncfs_ftruncate(newsize=%lld, fh=%d)\n", newsize, (int)fi->fh);
    
  retstat = ftruncate(fi->fh, newsize);
  if (retstat < 0)
    retstat = syncfs_error("syncfs_ftruncate ftruncate");
    
  return retstat;
}

/* Get attributes from an open file */
int pending_getattr(struct stat *statbuf, struct fuse_file_info *fi);
int syncfs_fgetattr(const char *, struct stat *statbuf, struct fuse_file_info *fi)
{
  int retstat = 0;
    
  log_msg("\nsyncfs_fgetattr(statbuf=%p, fh=%d)\n", statbuf, (int)fi->fh);

  if (fi->fh >= PENDING_FH_START)
    return pending_getattr(statbuf,fi);
    
  retstat = fstat(fi->fh, statbuf);
  if (retstat < 0)
    retstat = syncfs_error("syncfs_fgetattr fstat");
    
  return retstat;
}

/** Synchronize file contents
 *
 * If the datasync parameter is non-zero, then only the user data
 * should be flushed, not the meta data.
 *
 */
int syncfs_fsync(const char *, int datasync, struct fuse_file_info *fi)
{
  int retstat = 0;
    
  //log_msg("\nsyncfs_fsync(datasync=%d, fh=0x%d)\n", datasync, (int)fi->fh);
    
  if (datasync)
    retstat = fdatasync(fi->fh);
  else
    retstat = fsync(fi->fh);
    
  if (retstat < 0)
    syncfs_error("syncfs_fsync fsync");
    
  return retstat;
}

//////////
//
// Operations that involve the database
//

auto sql_get_fid = SQL("select fid from fileinfo where dir=? and name =?");
auto sql_is_local = SQL("select local from fileinfo where dir=? and name=?");

/** Remove a file */
auto sql_unlink = SQL("update fileinfo set dir=NULL, name=NULL, local=NULL where dir=? and name=?");
int syncfs_unlink(const char *path)
{
  int retstat = 0;
  char fpath[PATH_MAX];

  CHECKPATH(path, MOD_DIR);

  log_msg("\nsyncfs_unlink(path=\"%s\")\n",
          path);
  syncfs_fullpath(fpath, path);

  if (local_only(path)) {
    retstat = unlink(fpath);
    if (retstat < 0)
      return syncfs_error("syncfs_unlink (local) unlink");
    return 0;
  }

  DbMutex lock;

  try {

    bool local;
    sql_is_local(Path(path)).get(local);
    if (local) {
      retstat = unlink(fpath);
      if (retstat < 0)
        return syncfs_error("syncfs_unlink unlink");
    }

    sql_unlink.exec1(Path(path));
    metadata_thread->notify();

    return 0;

  } catch (SqlError & err) {
    log_msg("    ERROR: sql error: unlink %s: %s\n", path, err.msg.c_str());
    return -EIO;
  }
}

// both path and newpath are fs-relative
auto sql_exists = SQL("select fid from fileinfo where dir=? and name=?");
auto sql_rename = SQL("update fileinfo set dir=?, name=?, writable=? where dir=? and name=?");
//bool fdb_rename(const char *path, const char *newpath, DbMutex &);
int syncfs_rename(const char *path, const char *newpath)
{
  int retstat = 0;
  char fpath[PATH_MAX];
  char fnewpath[PATH_MAX];
    
  CHECKPATH(path, MOD_DIR);
  CHECKPATH(newpath, MOD_DIR);

  log_msg("\nsyncfs_rename(fpath=\"%s\", newpath=\"%s\")\n",
          path, newpath);
  syncfs_fullpath(fpath, path);
  syncfs_fullpath(fnewpath, newpath);

  if (local_only(path) && local_only (newpath)) {
    retstat = rename(fpath, fnewpath);
    if (retstat < 0)
      return syncfs_error("syncfs_rename unlink");
    return 0;
  } else if (local_only(path) || local_only (newpath)) {
    return -EPERM;
  }

  DbMutex lock;

  try {
    SqlTrans trans;
    bool local;
    auto exists = sql_exists(Path(path));
    if (exists.step()) {
      sql_is_local(Path(path)).get(local);
      sql_unlink.exec_nocheck(Path(newpath));
      sql_rename.exec1(Path(newpath), path_writable(newpath), Path(path));
    } else {
      // we have a directory
      // rename each path individually
      auto res = SELECT("select dir,name from fileinfo where dir is not null");
      auto orig_len = strlen(path);
      std::string newp;
      while (res.step()) {
	if (strncmp(res->dir, path, orig_len) != 0) continue;
	newp = newpath;
	newp += res->dir + orig_len;
	newp += res->name;
	//printf("=== %s%s => %s\n", dir,name, newp.c_str());
	sql_unlink.exec_nocheck(Path(newp.c_str()));
	sql_rename.exec1(Path(newp.c_str()), path_writable(newp.c_str()), res->dir, res->name);
	local = true;
      }
    }

    if (local) {
      retstat = rename(fpath, fnewpath);
      if (retstat < 0)
        return syncfs_error("syncfs_rename rename");
    }

    trans.commit();
    metadata_thread->notify();

    return 0;

  } catch (SqlError & err) {
    log_msg("    ERROR: sql error: rename %s -> %s: %s\n", path, newpath, err.msg.c_str());
    return -EIO;
  }
}

/** File open operation
 *
 * No creation, or truncation flags (O_CREAT, O_EXCL, O_TRUNC)
 * will be passed to open().  Open should check if the operation
 * is permitted for the given flags.  Optionally open may also
 * return an arbitrary filehandle in the fuse_file_info structure,
 * which will be passed to all file operations.
 *
 */

FileId fdb_open(const char * path, OpenState open_state) {
  FileId fid;
  sql_get_fid(Path(path)).get(fid);
  EXEC("update fileinfo set opened=max($open_state,opened),open_count=open_count + 1 where fid=$fid");
  return fid;
}
FileId fdb_create(const char * path) {
  return SQL("insert into fileinfo (dir, name, local, mtime, atime, opened, open_count, writable)"
	     "values (?1,?2,1,?3,?3,2,1,?4)").exec1(Path(path),time(NULL),path_writable(path));
}

auto sql_release_file = SQL("update fileinfo set opened=0, open_count = 0, atime=? where fid=?");
void update_file_after_mod(FileId fid, ssize_t size, time_t mtime) {
  auto cid = EXEC("insert into contentinfo (size) values ($size)");
  EXEC("update fileinfo set cid=$cid,mtime=$mtime where fid=$fid");
}

int fdb_close(FileId fid, int fd, bool cleanup = false) {
  try {
    int open_count,opened;
    SELECT("open_count,opened from fileinfo where fid=$fid").get(open_count,opened);
    struct stat st;
    auto now = time(NULL);
    if (open_count == 1) {
      sql_release_file.exec1(now, fid);
      if (fd >= 0 && opened == OpenedRW && !cleanup) {
        fstat(fd, &st);
	update_file_after_mod(fid, st.st_size, st.st_mtime);
      }
    } else {
      EXEC("update fileinfo set open_count = open_count -1, atime=$now where fid=$fid");      
    }
    return 0;
  } catch (SqlError & err) {
    log_msg("    ERROR: sql error on file close: %s\n", err.msg.c_str());
    return -EIO;
  }
}

int fetch_path(const char * path, FileId id, DbMutex & lock);
int pending_open(struct fuse_file_info *fi);

int syncfs_open(const char *path, struct fuse_file_info *fi)
{
  int retstat = 0;
  FileId fid = 0;
  int fd = -1;
  char fpath[PATH_MAX];

  bool readonly = !((fi->flags & O_WRONLY) == O_WRONLY || (fi->flags & O_RDWR) == O_RDWR);
  CHECKPATH(path, readonly ? READ : MOD_FILE);

  log_msg("\nsyncfs_open(path\"%s\")\n", path);
  
  if (strcmp(path, "/.proc/pending")== 0)
    return pending_open(fi);

  syncfs_fullpath(fpath, path);

  DbMutex lock;

  try {
    if (local_only(path))
      fid = -1;
    else
      fid = fdb_open(path, readonly ? OpenedRO : OpenedRW);
    
    bool local;
    if (fid == -1)
      local = true;
    else
      sql_is_local(Path(path)).get(local);

    if (!local) {
      auto ret = fetch_path(fpath, fid, lock);
      if (ret != 0) {
        retstat = -EIO;
        goto err;
      }
    }

    fd = open(fpath, fi->flags);
    if (fd < 0) {
      retstat = syncfs_error("syncfs_open open");
      goto err;
    }

    fi->fh = fd;
    log_msg("    fd = %d\n", fd);

    if (fid != -1 && !readonly)
      // mark the file as being modified and should be be uploaded until closed
      EXEC("update fileinfo set cid=NULL where fid=$fid");

  } catch (SqlError & err) {
    log_msg("    ERROR: sql error: open %s: %s\n", path, err.msg.c_str());
    retstat = -EIO;
    goto err;
  }

  if ((unsigned)fd >= opened_files.size()) opened_files.resize(fd + 1);
  opened_files[fd] = fid; 

  return 0;
err:
  if (fid > 0) fdb_close(fid, fd, true);
  if (fd >= 0) close(fd);
  return retstat;
}

/*  Create and open a file */
int syncfs_create(const char *path, mode_t mode, struct fuse_file_info *fi)
{
  char fpath[PATH_MAX];
  int fd;

  CHECKPATH(path, MOD_DIR);
    
  log_msg("\nsyncfs_create(path=\"%s\", mode=0%03o)\n",
          path, mode);
    
  DbMutex lock;

  syncfs_fullpath(fpath, path);
    
  fd = creat(fpath, mode);
  if (fd < 0)
    return syncfs_error("syncfs_create creat");
  fi->fh = fd;

  log_msg("    fh = %d\n", fd);

  FileId fid = 0;
  try {
    if (local_only(path)) 
      fid = -1;
    else
      fid =  fdb_create(path);

  } catch (SqlError & err) {
    close(fd);
    log_msg("    ERROR: sql error: create %s: %s\n", path, err.msg.c_str());
    return -EIO;
  }

  if ((unsigned)fd >= opened_files.size()) opened_files.resize(fd + 1);
  opened_files[fd] = fid; 

  return 0;
}

/** Release an open file
 *
 * Release is called when there are no more references to an open
 * file: all file descriptors are closed and all memory mappings
 * are unmapped.
 *
 * For every open() call there will be exactly one release() call
 * with the same flags and file descriptor.  It is possible to
 * have a file opened more than once, in which case only the last
 * release will mean, that no more reads/writes will happen on the
 * file.  The return value of release is ignored.
 */
int pending_release(fuse_file_info *fi);
int syncfs_release(const char * path, struct fuse_file_info *fi)
{
  int retstat = 0;
    
  log_msg("\nsyncfs_release(fh=%d path=%s)\n", (int)fi->fh, path);

  if (fi->fh >= PENDING_FH_START)
    return pending_release(fi);

  DbMutex lock;

  int fd = fi->fh;
  
  FileId fid = 0;
  if (fd < (int)opened_files.size()) {
    fid = opened_files[fd];
    opened_files[fd] = 0;
  }
  
  if (fid == 0) {
    log_msg("    ERROR: can not find fid for opened file: %s\n", path);
    return -EIO;
  }

  if (fid != -1)
    retstat = fdb_close(fid, fd);

  if (retstat != 0)
    return retstat;
  
  retstat = close(fi->fh);
  if (retstat != 0)
    return syncfs_error("syncfs_release close");

  local_part_thread->notify();

  return 0;
}

/** Get file attributes. */
int fdb_getattr(const char *path, struct stat *statbuf);
int syncfs_getattr(const char *path, struct stat *statbuf)
{
  int retstat = 0;
  char fpath[PATH_MAX];

  log_msg("\nsyncfs_getattr(path=\"%s\", statbuf=%p)\n",
          path, statbuf);

  if (strcmp(path, "/.proc") == 0) {
    statbuf->st_mode = S_IFDIR | 0755;
    statbuf->st_nlink = 2;
    return 0;
  } else if (strcmp(path, "/.proc/pending") == 0) {
    statbuf->st_mode = S_IFREG | 0444;
    statbuf->st_size = 0;
    return 0;
  } else if (strncmp(path, "/.proc/", 7) == 0) {
    return -ENOENT;
  }

  int ret = fdb_getattr(path, statbuf);
  // retstat is 0 on success, -1 on error, 1 if stat still needs to be called, 2 for a local only file
  if (ret == 0) return 0;
  if (ret < 0) return -EIO;
    
  syncfs_fullpath(fpath, path);
  if (ret > 0)
    retstat = lstat(fpath, statbuf);
  if (retstat != 0 && errno == ENOENT)
    retstat = -errno;
  else if (retstat != 0)
    retstat = syncfs_error("syncfs_getattr lstat");

  if (S_ISDIR(statbuf->st_mode)) {
    auto access = dir_access(path);
    if (access == ReadOnly)
      statbuf->st_mode &= 0770555;
  } else if (ret == 2) {
    auto access = path_access(path);
    if (access ==  NotAllowed) 
      statbuf->st_mode &= 0770000;
    else if (access == CreateOnly || access == ReadOnly)
      statbuf->st_mode &= 0770555;
  }
  
  return retstat;
}

// returns -1 on error, 0 if result, 1 if no result
int fdb_getattr(const char * path, struct stat *statbuf) {
  if (local_only(path)) return 2;
  try {
    DbMutex lock;
    auto res = SQL("select writable,size,atime,mtime "
		   "from fileinfo join contentinfo using (cid) "
		   "where dir=? and name=? and opened < 2")(Path(path));
    if (res.step()) {
      bool writable;
      res.get(writable, statbuf->st_size, statbuf->st_atime, statbuf->st_mtime);
      statbuf->st_mode = S_IFREG | (writable ? 0644 : 0444);
      statbuf->st_nlink = 1;
      statbuf->st_blocks = statbuf->st_size / 512 + (statbuf->st_size % 512 == 0 ?  0 : 1);
      statbuf->st_ctime = statbuf->st_mtime;
      return 0;
    } else {
      return 1;
    }
  } catch (SqlError & err) {
    log_msg("    ERROR: sql error: fdb_getattr: %s\n", err.msg.c_str());
    return 0;
  }
}

/** Read directory
 *
 * Uses this mode of operation:
 *
 * 1) The readdir implementation ignores the offset parameter, and
 * passes zero to the filler function's offset.  The filler
 * function will not return '1' (unless an error happens), so the
 * whole directory is read in a single readdir operation.  This
 * works just like the old getdir() method.
 *
 */
void fdb_readdir(const char * path, void * buf, fuse_fill_dir_t filler);
int syncfs_readdir(const char * path, void *buf, fuse_fill_dir_t filler, off_t offset,
               struct fuse_file_info *fi)
{
  int retstat = 0;
  DIR *dp;
  struct dirent *de;
  char fpath[PATH_MAX];

  if (path == NULL)
    return -ENOSYS;

  log_msg("\nsyncfs_readdir(buf=%p, filler=%p, offset=%lld, fi=%p)\n",
          buf, filler, offset, fi);

  if (strcmp(path, "/.proc") == 0) {
    filler(buf, ".", NULL, 0);
    filler(buf, "..", NULL, 0);
    filler(buf, "pending", NULL, 0);
    return 0;
  }

  syncfs_fullpath(fpath, path);

  dp = opendir(fpath);
  if (dp == NULL) {
    retstat = syncfs_error("syncfs_opendir opendir");
    return -1;
  }
    
  // Every directory contains at least two entries: . and ..  If my
  // first call to the system readdir() returns NULL I've got an
  // error; near as I can tell, that's the only condition under
  // which I can get an error from readdir()
  de = readdir(dp);
  if (de == 0) {
    retstat = syncfs_error("syncfs_readdir readdir");
    return retstat;
  }

  // Get Directory entries from file system.
  // This will copy the entire directory into the buffer.  The loop exits
  // when either the system readdir() returns NULL, or filler()
  // returns something non-zero.  The first case just means I've
  // read the whole directory; the second means the buffer is full.
  std::string new_path = fpath;
  new_path += '/';
  unsigned root_len = strlen(rootdir);
  unsigned base_len = new_path.size();
  if (strcmp(path,"/")==0)
    filler(buf, ".proc", NULL, 0);
  do {
    new_path.resize(base_len);
    new_path += de->d_name;
    struct stat st = {};
    stat(new_path.c_str(), &st);
    if (!S_ISREG(st.st_mode) || local_only(new_path.c_str() + root_len)) {
      //log_msg("    -- %s\n", de->d_name);
      if (filler(buf, de->d_name, NULL, 0) != 0) {
        log_msg("    ERROR syncfs_readdir filler:  buffer full");
        return -ENOMEM;
      }
    }
  } while ((de = readdir(dp)) != NULL);

  // Now get non-directory entries from database
  fdb_readdir(path, buf, filler);
    
  closedir(dp);
    
  return retstat;
}

void fdb_readdir(const char * dir, void * buf, fuse_fill_dir_t filler) {
  DbMutex lock;
  try {
    auto names = SQL("select name from fileinfo where dir=?||'/'")(strcmp(dir,"/")==0 ? "" : dir);
    while (names.step()) {
      const char * name;
      names.get(name);
      filler(buf, name, NULL, 0);
    }
  } catch (SqlError & err) {
    log_msg("    ERROR: sql error: fdb_readdir: %s\n", err.msg.c_str());
  }
}

//
// Misc operations that simply call existing ones
//

/** Change the size of a file */
// Note: Implemented by opening the file a using ftruncate to avoid a
// special case in the file info db code
int syncfs_truncate(const char *path, off_t newsize)
{
  int retstat;
  struct fuse_file_info fi = {};
  fi.flags = O_WRONLY;
  retstat = syncfs_open(path, &fi);
  if (retstat != 0) return retstat;
  retstat = syncfs_ftruncate(path, newsize, &fi);
  syncfs_release(path, &fi);  
  return retstat;
}

//////////
//
// Startup and Shutdown operations
//

void * uploader(void *);
void *syncfs_init(struct fuse_conn_info *conn)
{
  local_part_thread = new LocalPartThread();
  uploader_thread = new UploaderThread();
  extra_uploader_thread = new ExtraUploaderThread();
  metadata_thread = new MetadataThread();

  local_part_thread->create();
  uploader_thread->create();
  extra_uploader_thread->create();
  metadata_thread->create();
    
  log_msg("\nsyncfs_init()\n");
    
  return NULL;
}

/* Clean up filesystem. Called on filesystem exit. */
void syncfs_destroy(void *userdata)
{
  log_msg("\nsyncfs_destroy(userdata=%p)\n", userdata);
  // make sure all data is uploaded by giving the uploader a chance to
  // finish
  {
    DbMutex lock;
    exiting = true;
    local_part_thread->notify();
    uploader_thread->notify();
    if (extra_uploader_thread)
      extra_uploader_thread->notify();
    metadata_thread->notify();
  }
  pthread_join(metadata_thread->thread, NULL);
  pthread_join(uploader_thread->thread, NULL);
  if (extra_uploader_thread)
    pthread_join(extra_uploader_thread->thread, NULL);
  pthread_join(metadata_thread->thread, NULL);
  close_db();
  log_msg("    All done, EXITING\n");
}

//////////////////////////////////////////////////////////////////////////////
//
// Downloader
//

struct DownloadCond {
  FileId fid;
  pthread_cond_t cond;
  unsigned refs;
  int res; // result of download 0 on success non-zero on error
  DownloadCond * next;
  static DownloadCond * head;
  // returns a reference that can be used to delete the node without
  // having to find it again as would normally be the case with a
  // singly linked list
  static DownloadCond * & find(FileId to_find) {
    auto ptr = &head;
    while (*ptr) {
      if ((*ptr)->fid == to_find) return *ptr;
      ptr = &(*ptr)->next;
    }
    return *ptr;
  }
  static DownloadCond * get(FileId to_find) {
    auto node = find(to_find);
    if (!node)
      node = head = new DownloadCond{to_find, PTHREAD_COND_INITIALIZER, 0, 0, head};
    node->refs++;
    return node;
  }
  static void del(FileId to_del) {
    auto & node = find(to_del);
    auto tmp = node;
    node = node->next;
    delete tmp;
  }
  static int wait(FileId fid, DbMutex & lock) {
    assert(lock.locked);
    auto node = get(fid);
    pthread_cond_wait(&node->cond, &db_mutex);
    auto res = node->res;
    node->refs--;
    if (node->refs == 0) del(fid);
    return res;
  }
  static void notify(FileId fid, int res) {
    auto node = find(fid);
    if (!node) return;
    node->res = res;
    pthread_cond_broadcast(&node->cond);
  }
};
DownloadCond * DownloadCond::head = NULL; 

auto sql_download_info = SQL("select coalesce(remote_id,remote_path),downloading,mtime,size,checksum from fileinfo join contentinfo using (cid) "
                             "where fid=? and remote_path is not null");
int fetch_path(const char * fpath, FileId fid, DbMutex & lock) {
  assert(lock.locked);
  std::string remote_path;
  bool downloading;
  time_t mtime;
  size_t expected_size;
  const char * checksum_str;
  sql_download_info(fid).get(remote_path,downloading,mtime,expected_size,checksum_str);
  CheckSum expected_checksum = checksum_str;
  if (downloading) {
    log_msg("*** waiting on download %s\n", fpath);
    return DownloadCond::wait(fid, lock);
  } else {
    EXEC("update fileinfo set local=0, downloading=1 where fid=$fid");
    lock.unlock();
    log_msg("*** DOWNLOADING %s\n", fpath);
    int tries = 1;
  again:
    int ret = remote.download(&remote_state, remote_path.c_str(), fpath);
    if (ret != 0) goto finish;
    { struct utimbuf times = {time(NULL),mtime};
      utime(fpath, &times); }
    if (expected_checksum) {
      CheckSum checksum;
      remote.checksum(&remote_state, fpath, &checksum);
      if (/*size != expected_size || */expected_checksum != checksum) {
        if (tries < 2) {
          log_msg("*** error: size or checksum don't match, retrying in 10 seconds: %s\n", fpath);
          tries++;
          unlink(fpath);
          sleep(10);
          goto again;
        } else {
          log_msg("*** ERROR: download failed: size or checksum don't match %s\n", fpath);
          unlink(fpath);
          ret = -1;
        }
      } else {
        log_msg("*** checksum ok after downloading: %s\n", fpath);
      }
    }
  finish: 
    lock.lock();
    DownloadCond::notify(fid, ret);
    bool local = ret == 0 ? true : false;
    EXEC("update fileinfo set local=$local, downloading=0 where fid=$fid");
    return ret;
  }
}

//////////////////////////////////////////////////////////////////////////////
//
// Background tasks
//

static inline bool same_content(FileId fid, ContentId cid) {
  auto res = SELECT("select 1 from fileinfo where fid = $fid and cid = $cid");
  if (res.step()) return true;
  else return false;
}

auto sql_mark_failure = SQL("update fileinfo set remote_failures = remote_failures + 1 where fid = ?");

struct Fail {}; // thrown on remote failure
struct Exit {}; // thrown to exit thread

struct OpRes {
  bool did_something;
  ssize_t remote_space_change;
};

OpRes do_delete(FileId fid, int & more_to_do, time_t now, DbMutex & lock);
bool do_rename(FileId fid, int & more_to_do, time_t now, DbMutex & lock);
OpRes do_upload(FileId fid, int & more_to_do, time_t now, DbMutex & lock);

vector<FileId> want_to_remove;

bool LocalPartThread::do_work(DbMutex &lock) {
  assert(lock.locked);
  time_t now = time(NULL);
  // Delete any local files that are already upload and can be removed
  want_to_remove.clear();
  for (auto & r : SELECT("fid,path,atime,mtime,size,may_remove`bool "
			 "from want_to_remove order by round(size/1024/1024) desc, mtime")) {
    int status = ::may_remove(r.fid, r.path, r.atime, r.mtime, r.size, now);
    if (status > 0) {
      more_to_do = std::min(more_to_do, status);
      continue;
    } else if (status < 0) {
      EXEC("update fileinfo set keep_local=1 where fid=$r.fid");
      continue;
    } else if (r.may_remove) {
      char fpath[PATH_MAX];
      syncfs_fullpath(fpath, r.path);
      log_msg("*** REMOVING local copy of %s\n", r.path);
      unlink(fpath);
      EXEC("update fileinfo set local=0 where fid=$r.fid");
    } else {
      log_msg("--- want to remove but can't %s\n", r.path);
      want_to_remove.push_back(r.fid);
    }
  }
  if (!want_to_remove.empty())
    uploader_thread->notify();
  lock.yield();
  // Collect any files that need to be checksumed
  std::vector<FileId> need_checksum;
  for (auto fid : SELECT("fid from fileinfo join contentinfo using (cid) where checksum is null")) {
    need_checksum.push_back(fid);
  }
  for (auto fid : need_checksum) {
    if (exiting) throw Exit();
    auto res = SELECT("cid,dir||name as path from fileinfo join contentinfo using (cid) "
		      "where fid = $fid and checksum is null");
    if (!res.step()) continue;
    ContentId cid;
    std::string path;
    res.get(cid,path);
    res.reset();
    lock.unlock();
    char fpath[PATH_MAX];
    syncfs_fullpath(fpath, path.c_str());
    log_msg("*** CHECKSUMMING %s\n", fpath);
    CheckSum checksum;
    int ret = remote.checksum(&remote_state, fpath, &checksum);
    lock.lock();
    // FIXME: Also need to make sure the file was not deleted on us
    //  maybe this should be folded into same_content, not sure
    if (!same_content(fid,cid)) continue;
      // all good, let's continue
    if (ret != 0) {
      // this should not happen and if does we can't really continue
      // so just exit, do so be sending a SIGTERM so we can exit
      // cleanly and give the worker threads a chance to end at a good
      // point
      log_msg("*** FATAL: checksum failed on path: %s; exiting\n", fpath);
      kill(getpid(), SIGTERM);
      throw Exit();
    }
    EXEC("update contentinfo set checksum=$checksum.hex where cid = $cid");
  }
  uploader_thread->notify();
  if (extra_uploader_thread)
    extra_uploader_thread->notify();
  return false;
}

bool UploaderThread::do_work(DbMutex &lock) {
  assert(lock.locked);
  time_t now = time(NULL);
  vector<FileId> want_to_remove = ::want_to_remove;

  // Upload a single file that could be removed if upload
  for (auto fid : want_to_remove) {
    auto res = do_upload(fid, more_to_do, now, lock);
    if (res.did_something) {
      lock.lock();
      local_part_thread->notify();
      error_backoff = MIN_BACKOFF_ERROR;
      metadata_thread->notify();
      return true;
    }
  }

  // If we still did not do anything upload a single file
  vector<FileId> to_upload;
  lock.lock();
  for (auto fid : SELECT("fid from pending where to_upload order by size desc"))
    to_upload.push_back(fid);
  lock.unlock();
  for (auto fid : to_upload) {
    auto res = do_upload(fid, more_to_do, now, lock);
    if (res.did_something) {
      lock.lock();
      error_backoff = MIN_BACKOFF_ERROR;
      metadata_thread->notify();
      return true;
    }
  }
  
  return false;
}

bool ExtraUploaderThread::do_work(DbMutex &lock) {
  assert(lock.locked);
  time_t now = time(NULL);
  vector<FileId> to_upload;
  for (auto fid : SELECT("fid from pending where to_upload order by size"))
    to_upload.push_back(fid);
  lock.unlock();

  for (auto fid : to_upload) {
    auto res = do_upload(fid, more_to_do, now, lock);
    if (res.did_something) {
      lock.lock();
      error_backoff = MIN_BACKOFF_ERROR;
      metadata_thread->notify();
    }
  }
  return false;
}

bool MetadataThread::do_work(DbMutex &lock) {
  assert(lock.locked);
  time_t now = time(NULL);
  vector<FileId> to_delete;
  vector<FileId> to_rename;
  for (auto & r : SELECT("fid,to_delete`bool,to_rename`bool from pending where to_delete or to_rename")) {
    if (r.to_delete)
      to_delete.push_back(r.fid);
    else if (r.to_rename)
      to_rename.push_back(r.fid);
  }
  lock.unlock();
  for (auto fid : to_delete) {
    auto res = do_delete(fid, more_to_do, now, lock);
    if (res.did_something) error_backoff = MIN_BACKOFF_ERROR;
  }
  for (auto fid : to_rename) {
    bool did_something = do_rename(fid, more_to_do, now, lock);
    if (did_something) error_backoff = MIN_BACKOFF_ERROR;
  }
  return false;
}

OpRes do_delete(FileId fid, int & more_to_do, time_t now, DbMutex & lock) {
  //printf(">delete?> %lli\n", fid);
  lock.lock();
  if (exiting) throw Exit();
  auto res = SELECT("coalesce(remote_id,remote_path),size_delta,action is not null as in_progress "
		    "from pending join fileinfo using (fid) left join in_progress using (fid) "
		    "where to_delete and fid = $fid");
  if (!res.step()) return {false,0};
  string remote_id_path;
  int size_delta;
  res.get(remote_id_path,size_delta);
  res.reset();
  lock.unlock();
  log_msg("*** DELETING %s\n", remote_id_path.c_str());
  int ret = remote.del(&remote_state, remote_id_path.c_str());
  lock.lock();
  if (ret != 0) {sql_mark_failure.exec1(fid); throw Fail();}
  EXEC("update fileinfo set remote_id = null, remote_path = null, remote_failures = 0 where fid = $fid");
  return {true, size_delta};
}

bool do_rename(FileId fid, int & more_to_do, time_t now, DbMutex & lock) { 
  //printf(">rename?> %lli\n", cid);
  lock.lock();
  if (exiting) throw Exit();
  auto res = SELECT("remote_id,remote_path, dir||name as path,mtime,blocked_by,action is not null as in_progress "
		    "from pending join fileinfo f using (fid) left join in_progress using (fid) "
		    "where to_rename and fid = $fid");
  if (!res.step()) return false;
  string remote_id,remote_path,path;
  time_t mtime;
  FileId blocked_by;
  bool in_progress;
  res.get(remote_id,remote_path,path,mtime,blocked_by,in_progress);
  if (blocked_by != 0 || in_progress) {
    more_to_do = std::min(more_to_do, 1);
    return false;
  }
  if (remote_path.empty()) return false;
  if (remote_id.empty()) 
    remote_id = remote_path;
  res.reset();
  EXEC("insert into in_progress (fid, action, new_cid, new_path) values ($fid,'rename',0,$path)");  
  lock.unlock();
  log_msg("*** RENAMING %s -> %s\n", remote_path.c_str(), path.c_str());
  int ret = remote.rename(&remote_state, remote_id.c_str(), path.c_str(), mtime);
  lock.lock();
  EXEC("delete from in_progress where fid = $fid");
  if (ret != 0) {sql_mark_failure.exec1(fid); throw Fail();}
  EXEC("update fileinfo set remote_path = $path where fid = $fid");
  return true;
}

auto sql_mark_bad_upload = SQL("update fileinfo set remote_cid = NULL, remote_path = ? where fid = ?");
OpRes do_upload(FileId fid, int & more_to_do, time_t now, DbMutex & lock) {
  //printf(">upload?> %lli\n",  cid);
  lock.lock();
  if (exiting) throw Exit();
  auto res = SELECT("cid,remote_id,remote_path,dir||name as path,mtime,atime,l.size,checksum,blocked_by,size_delta,action is not null as in_progress "
		    "from pending join fileinfo using (fid) join contentinfo l using (cid) left join in_progress using (fid) "
		    "where to_upload and fid = $fid");
  if (!res.step()) return {false, 0};
  ContentId cid0;
  string remote_id,remote_path,path;
  time_t atime,mtime;
  int size;
  const char * checksum_str;
  FileId blocked_by;
  int size_delta;
  bool in_progress;
  res.get(cid0,remote_id,remote_path,path,mtime,atime,size,checksum_str,blocked_by,size_delta,in_progress);
  if (blocked_by != 0 || in_progress) {
    more_to_do = std::min(more_to_do, 1);
    return {false, 0};
  }
  CheckSum local_checksum = checksum_str;
  int status = should_upload(0,path.c_str(),atime,mtime,size,now);
  if (status > 0) {
    more_to_do = std::min(more_to_do, status);
    return {false, 0};
  } else if (status < 0) {
    return {false, 0};
  }
  res.reset();
  EXEC("insert into in_progress (fid, action, new_cid, new_path) values ($fid, 'upload', $cid0, $path)");
  lock.unlock();
  log_msg("*** UPLOADING %s\n", path.c_str());
  int ret;
  char id[256] = "";
  CheckSum checksum;
  char fpath[PATH_MAX];
  syncfs_fullpath(fpath, path.c_str());
  if (remote_id.empty()) {
    ret = remote.upload_new(&remote_state, fpath, path.c_str(), id, 256, &checksum);
  } else {
    ret = remote.replace(&remote_state, fpath, remote_id.c_str(), &checksum);
  }
  lock.lock();
  EXEC("delete from in_progress where fid = $fid");
  if (ret != 0) {sql_mark_failure.exec1(fid); throw Fail();}
  if (id[0] != '\0')
    EXEC("update fileinfo set remote_id = $id where fid = $fid");
  if (!same_content(fid,cid0)) {
    log_msg("*** WARNING file changed from under us, marking upload as bad %s\n", path.c_str());
    sql_mark_bad_upload.exec1(path.c_str(), fid); 
    throw Fail();
  }
  if (checksum != local_checksum) {
    log_msg("*** WARNING checksum mismatch after upload on path %s\n", path.c_str());
    sql_mark_bad_upload.exec1(path.c_str(), fid); 
    throw Fail();
  } else {
    log_msg("*** checksum ok after upload: %s\n", path.c_str());
  }
  EXEC("update fileinfo set remote_cid = $cid0, remote_path = $path, remote_failures = 0 where fid = $fid");
  more_to_do = std::min(more_to_do, REMOVE_WAIT);
  return {true, size_delta};
}

void * Worker::start() {
  log_msg("*** %s: starting\n", worker_name);
  DbMutex lock;
  more_to_do = INT_MAX;
  error_backoff = MIN_BACKOFF_ERROR;
 loop: try {
    log_msg("*** %s: new iteration\n", worker_name);
    more_to_do = INT_MAX;
    more_to_do_now = false;
    if (exiting) throw Exit();

    bool again = do_work(lock);
    lock.lock(); // make sure we are still locked

    if (exiting) throw Exit();
    waiting = true;
    error_backoff = MIN_BACKOFF_ERROR;
    if (more_to_do_now || again) {
      log_msg("*** %s: still more to do ...\n", worker_name);
      /* don't wait, but give other threads that are waiting on the lock a turn */
      lock.yield();
    } else if (more_to_do < INT_MAX) {
      log_msg("*** %s: more to do, waiting %d seconds\n", worker_name, more_to_do);
      struct timespec wait_until;
      clock_gettime(CLOCK_REALTIME, &wait_until);
      wait_until.tv_sec += more_to_do;
      pthread_cond_timedwait(&cond, &db_mutex, &wait_until);
    } else {
      log_msg("*** %s: all done, waiting for something to do\n", worker_name);
      pthread_cond_wait(&cond, &db_mutex);
    }
  } catch (Fail) {
    log_msg("*** %s: error, waiting %d seconds and trying again\n", worker_name, error_backoff);
    struct timespec wait_until, now;
    clock_gettime(CLOCK_REALTIME, &wait_until);
    wait_until.tv_sec += error_backoff;
    do {
      lock.lock();
      waiting = true;
      pthread_cond_timedwait(&cond, &db_mutex, &wait_until);
      if (exiting) goto exit;
      clock_gettime(CLOCK_REALTIME, &now);
    } while (now.tv_sec <wait_until.tv_sec);
    error_backoff = std::min(error_backoff * 2, MAX_BACKOFF_ERROR);
  } catch (Exit) {
    goto exit;
  } catch (SqlError & err) {
    log_msg("*** FATAL: %s: sqlite3: %s\n", worker_name, err.msg.c_str());
    kill(getpid(), SIGTERM);
    goto exit;
  }
  goto loop;
 exit:
  log_msg("*** %s: exiting\n", worker_name);
  return NULL;
}

void * Worker::thread_start(void * ptr) {
  auto ths = static_cast<Worker *>(ptr);
  return ths->start();
}


//////////////////////////////////////////////////////////////////////////////
//
// .proc filesystem functions
//
int pending_read(char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
  log_msg("pending_read...\n");
  DbMutex lock;
  auto idx = fi->fh - PENDING_FH_START;
  auto str = proc_file_content[idx];
  auto len = strlen(str);
  lock.unlock();
  if (offset >= len)
    return 0;
  if (offset + size >= len)
    size = len - offset;
  assert(offset + size <= len);
  memcpy(buf, str + offset, size);
  return len;
}

int pending_getattr(struct stat *statbuf, struct fuse_file_info *fi) {
  log_msg("pending_getattr...\n");
  DbMutex lock;
  auto idx = fi->fh - PENDING_FH_START;
  auto str = proc_file_content[idx];
  lock.unlock();
  statbuf->st_mode = S_IFDIR | 0755;
  statbuf->st_size = strlen(str);
  return 0;
}

int pending_open(struct fuse_file_info *fi) {
  log_msg("pending_open...\n");
  DbMutex lock;
  unsigned idx = 0;
  for (; idx < proc_file_content.size(); ++idx) {
    if (proc_file_content[idx] == NULL) break;
  }
  if (idx == proc_file_content.size())
    proc_file_content.resize(idx + 1);
  char * str = (char *)malloc(PENDING_MAX_SIZE);
  str[0] = '\0';
  proc_file_content[idx] = str;
  fi->direct_io = 1;
  fi->fh = PENDING_FH_START + idx;
  char * end = PENDING_MAX_SIZE + str;
  int opened_writing = SELECT("count(*)`int from fileinfo where opened >= 2").get();
  int need_checksum = SELECT("count(*)`int from fileinfo join contentinfo using (cid) where checksum is null").get();
  int to_delete,to_upload,to_rename;
  SELECT("sum(to_delete),sum(to_upload),sum(to_rename) from pending")
    .get(to_delete,to_upload,to_rename);
  auto report = [&](int cnt, const char * what) {
    if (cnt == 0) return;
    auto r = snprintf(str, end-str, "%d %s\n", cnt, what);
    assert(r > 0); // snprintf should not fail
    str += r;
  };
  report(opened_writing, "OPENED FOR WRITING");
  report(need_checksum, "need CHECKSUM");
  report(to_delete, "should be DELETED on the remote");
  report(to_upload, "should be UPLOADED to the remote");
  report(to_rename, "should be RENAMED on the remote");
  return 0;
}

int pending_release(fuse_file_info *fi) {
  log_msg("pending_release...\n");
  DbMutex lock;
  auto idx = fi->fh - PENDING_FH_START;
  proc_file_content[idx] = NULL;
  return 0;
}


//////////////////////////////////////////////////////////////////////////////
//
// Maintenance functions
//

static void fail(const char * format, ...);
enum PopulateAction {DefaultAction, SyncToRemote, SyncToLocal, EmptyTrash};

auto sql_insert_local = SQL("insert into local values (?,?,?,?,?)");
auto sql_insert_remote = SQL("insert into remote values (?,?,?,?,?)");

int get_local_listing(const char * dirname, unsigned root_len) {
  DIR * dirp = opendir(dirname);
  if (!dirp) return -1;
  std::string fullname = dirname;
  unsigned base_len = fullname.size();
  while (struct dirent * dir = readdir(dirp)) {
    if (strcmp(dir->d_name, ".") == 0 || strcmp(dir->d_name, "..") == 0) 
      continue;
    fullname.resize(base_len);
    fullname += dir->d_name;
    if (local_only(fullname.c_str() + root_len)) continue;
    //if (strcmp(fullname.c_str() + root_len, "/state") == 0) continue;
    struct stat st;
    int ret = stat(fullname.c_str(), &st);
    if (ret != 0) return -1;
    if (S_ISREG(st.st_mode)) {
      sql_insert_local.exec1(Path(fullname.c_str() + root_len), st.st_size, st.st_atime, st.st_mtime);
    } else if (S_ISDIR(st.st_mode)) {
      fullname += '/';
      get_local_listing(fullname.c_str(), root_len);
    } else {
      return -1;
    }
  }
  return 0;
}

void remote_listing_callback(void *, const char * id, const char * path, int size, time_t mtime, const CheckSum * checksum) {
  sql_insert_remote.exec1(id, path, size, mtime, checksum->hex);
}

// defined in remote.cpp for now
int mkpath(const char * orig_path);

void create_missing_dirs() {
  auto res = SELECT("distinct dir from fileinfo where dir is not null");
  while (res.step()) {
    const char * dir;
    res.get(dir);
    char fpath[PATH_MAX];
    syncfs_fullpath(fpath, dir);
    mkpath(fpath);
  }
}

class InsertFromRemote {
public:
  void operator() (const char * id, const char * path, int size, time_t mtime, const char * checksum) {
    auto fid = SQL("insert into fileinfo "
		   "(dir,name,writable,atime,mtime,remote_id,remote_path,local) "
		   "values(?1,?2,?3,?4,?4,?5,?6,0)")
      .exec1(Path(path), path_writable(path), mtime, id, path);
    auto cid = EXEC("insert into contentinfo (size,checksum) values ($size,$checksum)");
    EXEC("update fileinfo set cid = $cid, remote_cid = $cid where fid = $fid");
  }
};

void populate_from_remote(SqlTrans & trans) {
  auto res = SELECT("id,path,size,mtime,checksum from remote");
  InsertFromRemote insert;
  while (res.step()) {
    const char *remote_id, *path;
    int size;
    time_t mtime;
    const char * checksum;
    res.get(remote_id, path,size,mtime, checksum);
    insert(remote_id, path,size,mtime, checksum);
  }
  res = SELECT("dir,name,atime from local");
  auto set_local = SQL("update fileinfo set local=1,atime=? where dir=? and name=?");
  while (res.step()) {
    const char * dir, * name;
    time_t atime;
    res.get(dir,name,atime);
    set_local.exec_nocheck(atime, dir, name);
  }
  create_missing_dirs();
}

void populate_from_local(SqlTrans & trans) {
  auto res = SELECT("dir||name as path,size,atime,mtime from local");
  while (res.step()) {
    const char * path;
    int size;
    time_t atime,mtime;
    res.get(path,size,atime,mtime);
    auto fid = SQL("insert into fileinfo (dir,name,writable,atime,mtime,local) values (?,?,?,?,?,1)")
      .exec1(Path(path),path_writable(path),atime,mtime);
    auto cid = EXEC("insert into contentinfo (size) values ($size)");
    EXEC("update fileinfo set cid = $cid where fid = $fid");
  }
}

void cleanup_local() {
  auto res = SQL("select fid,dir||name as path,l.size, l.atime, l.mtime, opened, downloading "
                       "from local l join fileinfo f using (dir,name) "
                       "where opened > 0 or downloading ")();
  auto clear_downloading = SQL("update fileinfo set opened = 0, downloading = 0 where fid = ?");
  auto remove_from_local = SQL("delete from local where dir=? and name = ?");
  while (res.step()) {
    const char * path;
    FileId fid;
    int l_size;
    time_t l_mtime,l_atime;
    int opened;
    bool downloading;
    res.get(fid,path,l_size,l_atime,l_mtime,opened,downloading);
    if (downloading) {
      printf("note: removing partly downloaded file: %s\n", path);
      char fpath[PATH_MAX];
      syncfs_fullpath(fpath, path);
      unlink(fpath);
      clear_downloading.exec1(fid);
      remove_from_local.exec1(Path(path));
    } else if (opened == OpenedRO) {
      sql_release_file.exec1(time(NULL), fid);
    } else if (opened == OpenedRW) { 
      sql_release_file.exec1(time(NULL), fid);
      update_file_after_mod(fid, l_size, l_mtime);
    }
  }
}

int verify_local() {
  int errors = 0;
  auto res = SQL("select dir||name as path,fid,l.size != f.size diff, l.mtime as l_mtime, f.mtime as f_mtime "
		 "from local l left join (fileinfo join contentinfo using (cid)) f using (dir,name) "
		 "where l.mtime != f.mtime or l.size != f.size or f.fid is null " 
		 "order by dir,name")();
  while (res.step()) {
    const char * path;
    FileId fid;
    bool diff;
    time_t l_mtime,f_mtime;
    res.get(path, fid, diff,l_mtime,f_mtime);
    if (fid == 0) {
      printf("error: extra path in local filesystem: %s\n", path);
    } else if (diff) {
      printf("error: local content differ: %s\n", path);
    } else {
      // FIXME: Need to now verify checksums
      printf("error: different mtimes (%lu local vs %lu): %s\n", l_mtime, f_mtime, path);
    }
    errors++;
  }
  if (errors != 0) {
    printf("ERROR: Inconsistencies in local file system.\n");
  }
  return errors;
}

// Checks the local field to verify it reflects reality
// If not will update it.
// This means, amount other things, that is a file is locally deleted
// it will simply redownload if needed.
// Shoule be called with verify_local() to make sure there are not other problems
void sync_local_soft() {
  create_missing_dirs();
  SqlTrans trans;
  auto res = SQL("select *"
		 "from (select fid,local,l.dir is not null as l_local "
		 "      from fileinfo as f left join local as l using (dir,name)) "
		 "where local != l_local")();
  auto update_local = SQL("update fileinfo set local=? where fid=?");
  while (res.step()) {
    FileId fid;
    bool local, l_local;
    res.get(fid, local, l_local);
    if (local) {
      assert(!l_local);
      update_local.exec1(false, fid);
    } else if (l_local) {
      assert(!local);
      update_local.exec1(true, fid);
    }
  }
  trans.commit();
}

void sync_to_remote(bool noop, bool verbose) {
  SqlTrans trans;
  sql_exec("delete from fileinfo");
  sql_exec("delete from contentinfo");
  populate_from_local(trans);

  for (auto & r : SELECT("path,size,mtime,checksum,id`cstr from remote")) {
    auto cid = EXEC("insert into contentinfo (size,checksum) values ($r.size,$r.checksum)");
    auto l = SQL("select fid,mtime,size from fileinfo join contentinfo using (cid) where dir = ? and name = ?")(Path(r.path));
    if (l.step()) {
      EXEC("update fileinfo set remote_cid = $cid, remote_id = $r.id, remote_path = $r.path where fid = $l->fid");
      if (r.size == l->size && r.mtime == l->mtime)
	// we are assuming the content is the same so link up the cid
	EXEC("update fileinfo set cid = $cid where fid = $l->fid");
      else
	// since the cid differ a new version will be uploaded
	printf("will overright: %s\n", r.path);
    } else {
      printf("will delete: %s\n", r.path);
      EXEC("insert into fileinfo (remote_id,remote_path,remote_cid) values ($r.id,$r.path,$cid)");
    }
  }

  if (verbose) {
    for (auto path : SELECT("select dir||name as path from fileinfo where remote_cid is null"))
      printf("marked to upload: %s\n", path);
  }

  if (noop) {
    trans.rollback();
    printf("NOT PERFORMING SYNC.  RESTORING TO PREVIOUS STATE.\n");
  } else {
    trans.commit();
  }
}

int verify_remote() {
  //sql_exec(sql_remote_diff_cleanup);
  int errors = 0;
  SqlResult res = SELECT("path from remote_only");
  while (res.step()) {
    const char * path;
    res.get(path);
    printf("error: extra path in remote filesystem: %s\n", path);
    errors++;
  }

  res = SELECT("path, in_remote, diff, r_mtime, f_mtime from remote_diff");
  while (res.step()) {
    const char * path;
    bool in_remote,diff;
    time_t r_mtime, f_mtime;
    res.get(path,in_remote,diff,r_mtime,f_mtime);
    if (!in_remote) {
      printf("error: path should exist but doesn't in remote filesystem: %s\n", path);
    } else if (diff) {
      printf("error: remote content differ: %s\n", path);
    } else {
      printf("error: different mtimes (%lu remote vs %lu): %s\n", r_mtime, f_mtime, path);
    }
    errors++;
  }
  if (errors != 0) {
    printf("ERROR: Inconsistencies in remote file system.\n");
  }
  return errors;
}

void sync_to_local(bool noop, bool verbose) {
  SqlTrans trans;
  sql_exec("delete from fileinfo");
  sql_exec("delete from contentinfo");

  populate_from_remote(trans);

  auto res = SELECT("select dir||name as path, fid, l.size, l.atime, l.mtime "
		    "from local l left join (fileinfo left join contentinfo using (cid)) f using (dir,name) "
		    "where l.mtime != f.mtime or l.size != f.size or f.fid is null "
		    "order by dir,name");
  while (res.step()) {
    auto & r = res.get();
    if (r.fid == 0) 
      printf("will remove: %s\n", r.path);
    else
      printf("will replace: %s\n", r.path);
    if (!noop) {
      char fpath[PATH_MAX];
      syncfs_fullpath(fpath, r.path);
      int res = unlink(fpath);
      if (res != 0)
        fail("Could not remove local file: %s", fpath);
      if (r.fid != 0)
	EXEC("update fileinfo set local=0, cid=NULL where fid=$r.fid");
    }
  }

  if (verbose) {
    auto res = SELECT("select dir||name as path from fileinfo where not local and cid is not null");
    while (res.step()) {
      const char * path;
      res.get(path);
      printf("marked to download: %s\n", path);
    }
  }

  if (noop) {
    trans.rollback();
    printf("NOT PERFORMING SYNC.  RESTORING TO PREVIOUS STATE.\n");
  } else {
    trans.commit();
  }
}

void populate_db(PopulateAction action, bool noop, bool verbose) {
  try {
    char fpath[PATH_MAX];
    syncfs_fullpath(fpath, "/");
    get_local_listing(fpath, strlen(fpath)-1);
    remote.list(&remote_state, remote_listing_callback, NULL);
    bool database_empty = SELECT("count(*) == 0 `bool from fileinfo").get();
    bool local_empty = SELECT("count(*) == 0 `bool from local").get();
    bool remote_empty = SELECT("count(*) == 0 `bool from remote").get();
    if (action == SyncToRemote) {
      printf("Sync. to remote...\n");
      sync_to_remote(noop, verbose);
      if (noop) exit(1);
    } else if (action == SyncToLocal) {
      printf("Sync. to local...\n");
      sync_to_local(noop, verbose);
      if (noop) exit(1);
    } else if (database_empty) {
      if (local_empty && remote_empty) {
        /* nothing to do */
      } else if (remote_empty) {
        printf("Populating from local...\n");
        SqlTrans trans;
        populate_from_local(trans);
        trans.commit();
      } else {
        printf("Populating from remote...\n");
        SqlTrans trans;
        populate_from_remote(trans);
        trans.commit();
        if (verify_local() != 0) {
          sql_exec("delete from contentinfo; delete from fileinfo;");
          exit(1);
        }
      }
    } else {
      cleanup_local();
      sync_local_soft();
      printf("Verifying local and remote are in sync...\n");
      auto res1 = verify_local();
      auto res2 = verify_remote();
      if (res1 != 0 || res2 != 0) exit(1);
    }
  } catch (SqlError & err) {
    fprintf(stderr, "ERROR: sqlite3: %s\n", err.msg.c_str());
    exit(-1);
  }
}

//////////////////////////////////////////////////////////////////////////////
//
// Init code
//

static void read_config() {
  using json::Value;
  const char * fn = ".etc/syncfs.conf";
  auto f = fopen(fn, "r");
  if (!f) {
    printf("Error: unable to read \"%s\".\n", fn);
    exit(1);
  }
  const char * key = NULL;
  const char * path = NULL;
  const char * subkey = NULL;
  char readBuffer[1024*16];
  try {
    json::Document conf;
    json::FileReadStream is(f, readBuffer, sizeof(readBuffer));
    conf.ParseStream<json::kParseCommentsFlag>(is);
    fclose(f);

    key = "remote";
    auto r = conf["remote"].GetString();
    if (strcmp(r, "drive") == 0)
      remote = drive_remote;
    else if (strcmp(r, "file") == 0)
      remote = file_remote;
    else
      throw JsonException("Expected one of: drive, file\n");

    key = "local_only";
    local_only.data.push_back({"/.var/", true});
    local_only.data.push_back({"/.etc/", true});
    for (auto & v : GetMember(key, EmptyObject, conf)) {
      local_only.data.push_back({v.name.GetString(), v.value.GetBool()});
    }
    local_only.data.prioritize(2);
    local_only.data.push_back({"/", false});

    key = "path_access";
    path_access.data.push_back({"/.proc/pending", ReadOnly});
    path_access.data.push_back({"/.proc/", NotAllowed});
    path_access.data.push_back({"/.var/", ReadOnly});
    path_access.data.push_back({"/.etc/", ReadWrite});
    for (auto & v : GetMember(key, EmptyObject, conf)) {
      path = v.name.GetString();
      auto val = v.value.GetString();
      auto access = (strcmp(val, "NotAllowed") == 0 ? NotAllowed : 
		     strcmp(val, "ReadOnly") == 0 ? ReadOnly : 
		     strcmp(val, "CreateOnly") == 0 ? CreateOnly :
		     strcmp(val, "ReadWrite") == 0 ? ReadWrite : 
		     throw JsonException("Expected one of: NotAllowed, ReadOnly, CreateOnly, ReadWrite"));
      path_access.data.push_back({v.name.GetString(), access});
    }
    path_access.data.prioritize(3);
    path_access.data.push_back({"/", ReadWrite});

    auto get_value = [&conf,&subkey](const char * str, int32_t def, const Value & v) {
      subkey = str;
      auto i = v.FindMember(str);
      if (i == v.MemberEnd()) return def;
      if (i->value.IsString() && i->value.GetString()[0] == '$')
	return conf[i->value.GetString()].GetInt();
      return i->value.GetInt();
    };

    key = "should_upload";
    for (auto & v : GetMember(key, EmptyObject, conf)) {
      path = v.name.GetString();
      should_upload.data.push_back({path,
				    {get_value("min_wait", -1, v.value),
				     get_value("max_wait", -1, v.value),
				     get_value("keep_size", -1, v.value)}});
    }
    should_upload.data.prioritize();
    should_upload.data.push_back({"/", {UPLOAD_WAIT, FOREVER, 0}});

    key = "may_remove";
    for (auto & v : GetMember(key, EmptyObject, conf)) {
      path = v.name.GetString();
      if (v.value.IsBool()) {
	if (v.value.GetBool() == false)
	  may_remove.data.push_back({path, {FOREVER}});
	else
	  throw JsonException("Invalid value for may_remove path.");
      } else {
	may_remove.data.push_back({path, {get_value("wait", -1, v.value)}});
      }
    }
    may_remove.data.prioritize();
    may_remove.data.push_back({"/", {REMOVE_WAIT}});
    //for (auto & v : may_remove.data) {
    //  printf(">may remove>%s %d\n", v.first.path.c_str(), v.second.wait);
    //}

  } catch (JsonException & err) {
    fprintf(stderr, "ERROR: %s: ", fn);
    if (key) fprintf(stderr, "%s: ", key);
    if (path) fprintf(stderr, "%s: ", path);
    if (subkey) fprintf(stderr, "%s: ", subkey);
    fprintf(stderr, "%s\n", err.what());
    exit(1);
  }
}

static void fail(const char * format, ...) {
  va_list ap;
  va_start(ap, format);

  fprintf(stderr, "ERROR: ");
  vfprintf(stderr, format, ap);
  if (errno)
    fprintf(stderr, ": %s\n", strerror(errno));
  else
    fprintf(stderr, "\n");
  exit (1);
}

void sql_trace(void*, const char* str) {
  log_msg("    sql: %s\n", str);
}

void init_db(const char * dir, bool reset_db) {
  int ret = 0;
  check_schema(reset_db);
  try {
    const char * dbhome = ".var";
    mkdir(dbhome,0777);
    const char * dbfile = ".var/fileinfo.db";
    ret = sqlite3_open(dbfile, &db);
    if (ret != 0) throw SqlError(ret, db);
    sqlite3_busy_timeout(db, 20*60*1000); // 20 minutes
    if (LOG_SQL)
      sqlite3_trace(db, sql_trace, NULL);
    sql_exec("PRAGMA synchronous = NORMAL"); // we can rebuild on an os crash
    bool need_tables;
    SQL("select count(*) ==0 from sqlite_master where name='fileinfo'").get(need_tables);
    if (reset_db)
      sql_exec("drop table if exists fileinfo; "
	       "drop table if exists contentinfo; "
	       "drop table if exists in_progress; ");
    sql_exec(SqL_schema);
  } catch (SqlError & err) {
    fprintf(stderr, "ERROR: sqlite3: %s\n", err.msg.c_str());
    exit(-1);
  }
  auto failures = 0;
  for (auto q : SqL_queries) {
    try {
      SqlStmtBase(&q).prepare();
    } catch (SqlError & err) {
      fprintf(stderr, "ERROR: Prepare failed:\n");
      fprintf(stderr, "  %s\n", err.msg.c_str());
      failures++;
    }
  }
  if (failures > 0) 
    exit(1);
}

void close_db() {
  if (db != NULL)
    sqlite3_close(db);
}

//////////////////////////////////////////////////////////////////////////////
//
// Globals from json.hpp for lack of a better place to put them
//

const json::Value emptyObjectValue = std::move(json::Value().SetObject());
json::Value::ConstObject EmptyObject = emptyObjectValue.GetObject();

//////////////////////////////////////////////////////////////////////////////
//
// Main
//

static void init_fuse_ops(fuse_operations & oper);

void syncfs_usage()
{
  fprintf(stderr, "usage: syncfs [FUSE and mount options] rootDir mountPoint\n");
  abort();
}

int main(int argc, char * *argv)
{
  if ((getuid() == 0) || (geteuid() == 0)) {
    fprintf(stderr, "Running SyncFS as root opens unnacceptable security holes\n");
    return 1;
  }
  bool reset_db = false;
  auto action = DefaultAction;
  bool noop = true;
  if (argc > 1) {
   if (strcmp(argv[1], "--reset-db") == 0) 
      {reset_db = true;}
    else if (strcmp(argv[1], "--sync-to-remote-noop") == 0) 
      {action = SyncToRemote; noop = true;}
    else if (strcmp(argv[1], "--sync-to-remote-for-real") == 0)
      {action = SyncToRemote; noop = false;}
    else if (strcmp(argv[1], "--sync-to-local-noop") == 0)
      {action = SyncToLocal; noop = true;}
    else if (strcmp(argv[1], "--sync-to-local-for-real") == 0)
      {action = SyncToLocal; noop = false;}
    else if (strcmp(argv[1], "--empty-trash") == 0)
      {action = EmptyTrash;}
    if (reset_db || action != DefaultAction) { /* i.e., some action */
      argc--;
      argv[1] = argv[0];
      argv++;
    }
  }

  // Perform some sanity checking on the command line
  // there are enough arguments, and that neither of the last two
  // start with a hyphen (this will break if you actually have a
  // rootpoint or mountpoint whose name starts with a hyphen, but so
  // will a zillion other programs)
  if ((argc < 3) || (argv[argc-2][0] == '-') || (argv[argc-1][0] == '-'))
    syncfs_usage();

  // Pull the rootdir out of the argument list and save it in my
  // internal data
  rootdir = realpath(argv[argc-2], NULL);
  if (rootdir == NULL) {
    perror(rootdir);
    exit(1);
  }
  printf(">rootdir> %s\n", rootdir);
  argv[argc-2] = argv[argc-1];
  argv[argc-1] = NULL;
  argc--;

  const char * mntdir = realpath(argv[argc-1], NULL);
  if (mntdir == NULL) {
    perror(mntdir);
    exit(1);
  }
  argv[argc-1] = realpath(argv[argc-1], NULL);

  int ret = chdir(rootdir);
  if (ret != 0) fail("chdir: %s", rootdir);
  mkdir(".var", 0777);

  char *new_argv[argc+2];
  new_argv[0] = argv[0];
  new_argv[1] = (char *)"-o";
  char opts[64];
  snprintf(opts, 64, "hard_remove,uid=%u,gid=%u", geteuid(), getegid());
  new_argv[2] = opts;
  for (int i = 1; i < argc; ++i)
    new_argv[i+2] = argv[i];
  argc += 2;
  argv = new_argv;

  read_config();

  logfile = fopen(".var/syncfs.log", "a");
  if (logfile == NULL) {
    perror("logfile");
    exit(EXIT_FAILURE);
  }
  auto t = time(NULL);
  auto tm = localtime(&t);
  char datestr[64];
  strftime(datestr, 64, "%F %T %Z", tm);
  log_msg("log start: time = %s\n", datestr);
  // set logfile to line buffering
  setvbuf(logfile, NULL, _IOLBF, 0);

  remote.init(".", &remote_state);

  if (action == EmptyTrash) {
    if (remote.empty_trash) {
      return remote.empty_trash(&remote_state);
    } else {
      printf("ERROR: Remote does not support emptying trash\n");
      exit(1);
    }
  }

  DbMutex lock;
  init_db(rootdir, reset_db);
  
  populate_db(action,noop,false);
  lock.unlock();

  fuse_operations oper;
  init_fuse_ops(oper);

  // turn over control to fuse
  fprintf(stderr, "about to call fuse_main...\n");
  ret = chdir("/"); // fuse will do this most of the time, but not
                    // when the "-f" option is given, so do it now to
                    // avoid inconsistent behavior
  if (ret != 0) fail("chdir: %s", rootdir);
  int fuse_stat = fuse_main(argc, argv, &oper, NULL);
  fprintf(stderr, "fuse_main returned %d\n", fuse_stat);

  close_db();
    
  return fuse_stat;
}

static void init_fuse_ops(fuse_operations & oper) {
  oper = {};
  oper.getattr = syncfs_getattr;
  oper.mkdir = syncfs_mkdir;
  oper.unlink = syncfs_unlink;
  oper.rmdir = syncfs_rmdir;
  oper.rename = syncfs_rename;
  oper.open = syncfs_open;
  oper.read = syncfs_read;
  oper.write = syncfs_write;
  oper.release = syncfs_release;
  oper.fsync = syncfs_fsync;
  oper.readdir = syncfs_readdir;
  oper.init = syncfs_init;
  oper.destroy = syncfs_destroy;
  oper.create = syncfs_create;
  oper.ftruncate = syncfs_ftruncate;
  oper.truncate = syncfs_truncate;
  oper.fgetattr = syncfs_fgetattr;
  oper.flag_nullpath_ok = 1;
};

