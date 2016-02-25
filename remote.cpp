#include <string>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <dirent.h>
#include <utime.h>
#include <math.h>

#include "json.hpp"
#include "remote.h"

static json::Document conf;
static const char * loc = NULL;

static const char * rootdir = NULL;
static FILE * rlog;

pthread_mutex_t rand_mutex = PTHREAD_MUTEX_INITIALIZER;
int myrand() {
  pthread_mutex_lock(&rand_mutex);
  int val = rand();
  pthread_mutex_unlock(&rand_mutex);
  return val;
}

using std::string;

static string fullpath(const char * base, const char * path) {
  assert(path[0] == '/');
  string ret = base;
  ret += path;
  return ret;
}

static int init(const char * rdir, RemoteState *) {
  rootdir = rdir;
  using json::Value;
  const char * fn = ".etc/remote.conf";
  auto f = fopen(fn, "r");
  if (!f) {
    printf("Error: unable to read \"%s\".\n", fn);
    exit(1);
  }
  try {
    char readBuffer[1024*16];
    json::FileReadStream is(f, readBuffer, sizeof(readBuffer));
    conf.ParseStream<json::kParseCommentsFlag>(is);
    fclose(f);

    loc = GetMember("path", loc, conf);
  } catch (JsonException & err) {
    fprintf(stderr, "ERROR: %s: ", fn);
    fprintf(stderr, "%s\n", err.what());
  }
  struct stat sb;
  loc = realpath(loc, NULL);
  if (loc == NULL) {
    printf("Path does not exist: %s\n", conf["path"].GetString());
    exit(1);
  }
  if (access(loc, R_OK|W_OK|X_OK) != 0) {
    printf("Unable to access: %s\n", loc);
    exit(1);
  }
  if (stat(loc, &sb) != 0 || !S_ISDIR(sb.st_mode)) {
    printf("Error: not a directory: %s", loc);
    exit(1);
  }

  rlog = fopen(".var/remote.log", "w");
  if (rlog == NULL) {
    perror("remote logfile");
    exit(EXIT_FAILURE);
  }
  setvbuf(rlog, NULL, _IOLBF, 0);
  return 0;
}

static int kill(RemoteState *) {
  return 0;
}

int mkpath(const char * orig_path) {
  char file_path[strlen(orig_path) + 1];
  strcpy(file_path, orig_path);
  char* p;
  for (p=strchr(file_path+1, '/'); p; p=strchr(p+1, '/')) {
    *p='\0';
    if (mkdir(file_path, 0777)==-1) {
      if (errno!=EEXIST) { *p='/'; return -1; }
    }
    *p='/';
  }
  return 0;
}

int copy_file(const char * from, const char * to) {
  int src = open(from, O_RDONLY);
  if (src < 0) {
    fprintf(rlog, "ERROR: could not open \"%s\" for reading\n", from);
    return errno;
  }
  int res = mkpath(to);
  unlink(to);
  int dst = open(to, O_WRONLY|O_CREAT|O_TRUNC, 0666);
  if (res != 0 || dst < 0) {
    fprintf(rlog, "ERROR: could not open \"%s\" for writing\n", to);
    return errno;
  }
  static const unsigned buf_sz = 1024*16;
  char buf[buf_sz];
  ssize_t sz,sz2=0;
  while (sz = read(src, buf, buf_sz), sz > 0) {
    sz2 = write(dst, buf, sz);
    if (sz2 < 0) break;
  }

  close(dst);
  close(src);
  if (sz < 0 || sz2 < 0) {
    errno = EIO;
    fprintf(rlog, "ERROR: copy from \"%s\" to \"%s\" failed\n", from, to);
    return errno;
  }

  struct stat st = {};
  stat(from, &st);
  struct utimbuf times = {st.st_atime,st.st_mtime};
  utime(to, &times);

  //fprintf(rlog, "done copying %s -> %s\n", from, to);
  return 0;
}

static int download(RemoteState *, const char * from0, const char * to) { 
  double delay_f = exp2(exp2(1.5*myrand()/RAND_MAX) - 1)-1; // between 0 and ~2.6
  time_t sec = (time_t)delay_f;
  timespec delay = {sec, (long)(1000000000*(delay_f - sec))};
  int res;
  do {
    res = nanosleep(&delay,&delay);
  } while (res == EINTR);
  fprintf(rlog, "downloading %s -> %s (with delay %f)\n", from0, to, delay_f);
  auto from = fullpath(loc, from0);
  return copy_file(from.c_str(), to);
}

static int upload(const char * from, const char * to0, CheckSum * checksum) {
  if (myrand() < RAND_MAX/3) {
    fprintf(rlog, "ERROR: random error uploading file %s -> %s\n", from, to0);
    errno = EINTR;
    return -1;
  }
  fprintf(rlog, "uploading %s -> %s\n", from, to0);
  auto to   = fullpath(loc, to0);
  int res = copy_file(from, to.c_str());
  if (res != 0) return res;
  checksum->hex[0] = '\0';
  return 0;
}

static int upload_new(RemoteState *, const char * from, const char * to, char * id, size_t id_sz, CheckSum * checksum) {
  int ret = upload(from, to, checksum);
  id[0] = '\0';
  return ret;
}

// Upload and replace a path. If "to" will be an internal id if the
// remote uses it.
static int replace(RemoteState *, const char * from, const char * to, CheckSum * checksum) {
  return upload(from, to, checksum);
}

static int rename(RemoteState *, const char * from0, const char * to0, time_t) {
  if (myrand() < RAND_MAX/5) {
    fprintf(rlog, "ERROR: random error renaming file %s -> %s\n", from0, to0);
    errno = EINTR;
    return -1;
  }
  fprintf(rlog, "renaming %s -> %s\n", from0, to0);
  auto from = fullpath(loc, from0);
  auto to   = fullpath(loc, to0);
  mkpath(to.c_str());
  return rename(from.c_str(), to.c_str());
}

static int del(RemoteState *, const char * path) {
  if (myrand() < RAND_MAX/5) {
    fprintf(rlog, "ERROR: random deleting file %s\n", path);
    errno = EINTR;
    return -1;
  }
  fprintf(rlog, "deleting %s\n", path);
  auto to_del = fullpath(loc, path);
  return unlink(to_del.c_str());
}


static int get_listing(const char * dirname, unsigned root_len, RemoteOpsListCallback callback, void * data) {
  DIR * dirp = opendir(dirname);
  if (!dirp) return -1;
  std::string fullname = dirname;
  unsigned base_len = fullname.size();
  while (struct dirent * dir = readdir(dirp)) {
    if (strcmp(dir->d_name, ".") == 0 || strcmp(dir->d_name, "..") == 0) 
      continue;
    fullname.resize(base_len);
    fullname += dir->d_name;
    if (strcmp(fullname.c_str() + root_len, "/log") == 0) continue;
    struct stat st;
    int ret = stat(fullname.c_str(), &st);
    if (ret != 0) return -1;
    CheckSum checksum = {""};
    if (S_ISREG(st.st_mode)) {
      callback(data, NULL, fullname.c_str() + root_len, st.st_size, st.st_mtime, &checksum);
    } else if (S_ISDIR(st.st_mode)) {
      fullname += '/';
      get_listing(fullname.c_str(), root_len, callback, data);
    } else {
      return -1;
    }
  }
  return 0;
}

static int list(RemoteState *, RemoteOpsListCallback callback, void * data) {
  string root = fullpath(loc, "/");
  return get_listing(root.c_str(), root.size() -1, callback, data);
}

static int checksum(RemoteState *, const char *, CheckSum * checksum) {
  checksum->hex[0] = '\0';
  return 0;
}

RemoteOps file_remote {
  init, kill, list, checksum, download, upload_new, replace, rename, del
};

