#include <string>
#include <vector>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <pthread.h>
#include <curl/curl.h>
#include <errno.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <assert.h>
#include <fcntl.h>

#include "json.hpp"
#include "remote.h"

using json::Value;
using json::StringRef;

using std::string;

/////////////////////////////////////////////////////////////////////////////
//
// Config options
//

static json::Document conf;

const char * client_id="340912995903-qv776m9tl40gipschqplc2rl69s7i0pk.apps.googleusercontent.com";
const char * client_secret="J38Wj0akdnTirJazRnIxCKBa";
const char * redirect="urn:ietf:wg:oauth:2.0:oob";
const char * scope = "https://www.googleapis.com/auth/drive";

const char * drive_auth = ".var/drive.auth";
bool use_delete = false;

const char * remote_dir;

//////////////////////////////////////////////////////////////////////////////
//
// Global state
//

static FILE * rlog = stderr;
//const char * localdir = NULL;
string root_id;

//////////////////////////////////////////////////////////////////////////////
//
// Thread safety for SSL libraries
//

/* we have this global to let the callback get easy access to it */ 
#ifdef USE_OPENSSL

static pthread_mutex_t *lockarray;

#include <openssl/crypto.h>
static void lock_callback(int mode, int type, const char *file, int line)
{
  (void)file;
  (void)line;
  if(mode & CRYPTO_LOCK) {
    pthread_mutex_lock(&(lockarray[type]));
  }
  else {
    pthread_mutex_unlock(&(lockarray[type]));
  }
}
 
static unsigned long thread_id(void)
{
  unsigned long ret;
 
  ret=(unsigned long)pthread_self();
  return ret;
}
 
static void init_locks(void)
{
  int i;
 
  lockarray=(pthread_mutex_t *)OPENSSL_malloc(CRYPTO_num_locks() *
					      sizeof(pthread_mutex_t));
  for(i=0; i<CRYPTO_num_locks(); i++) {
    pthread_mutex_init(&(lockarray[i]), NULL);
  }
 
  CRYPTO_set_id_callback((unsigned long (*)())thread_id);
  CRYPTO_set_locking_callback(lock_callback);
}
 
static void kill_locks(void)
{
  int i;
 
  CRYPTO_set_locking_callback(NULL);
  for(i=0; i<CRYPTO_num_locks(); i++)
    pthread_mutex_destroy(&(lockarray[i]));
 
  OPENSSL_free(lockarray);
}
#endif

#ifdef USE_GNUTLS
#include <gcrypt.h>
#include <errno.h>
 
GCRY_THREAD_OPTION_PTHREAD_IMPL;
 
void init_locks()
{
  gcry_control(GCRYCTL_SET_THREAD_CBS);
}
 
#define kill_locks()
#endif

void pre_init() {
  curl_global_init(CURL_GLOBAL_ALL);
  init_locks();
}

//////////////////////////////////////////////////////////////////////////////
//
// md5
//

#ifdef USE_OPENSSL
#include <openssl/md5.h>
struct ComputeMD5 {
  struct Hash {
    // binary hash
    unsigned char bin[128/8];
  };
  MD5_CTX ctx;
  ComputeMD5() {MD5_Init(&ctx);}
  void add(void * data, size_t len) {MD5_Update(&ctx, data, len);}
  Hash output() {Hash md5; MD5_Final(md5.bin, &ctx); return md5;}
  ~ComputeMD5() {}
};
#endif
#ifdef USE_GNUTLS

#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>

struct ComputeMD5 {
  struct Hash {
    // binary hash
    char bin[128/8];
  };
  gnutls_hash_hd_t dig;
  ComputeMD5() {gnutls_hash_init(&dig, GNUTLS_DIG_MD5);}
  void add(void * data, size_t len) {gnutls_hash(dig, data, len);}
  Hash output() {Hash md5; gnutls_hash_output(dig, &md5.bin); return md5;}
  ~ComputeMD5() {gnutls_hash_deinit(dig,NULL);}
};

#endif

void md5_bin_to_hex(const ComputeMD5::Hash & in, CheckSum & out) {
  snprintf(out.hex, CHECKSUM_SZ, "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
	   (unsigned char)in.bin[0], 
	   (unsigned char)in.bin[1],
	   (unsigned char)in.bin[2],
	   (unsigned char)in.bin[3],
	   (unsigned char)in.bin[4],
	   (unsigned char)in.bin[5],
	   (unsigned char)in.bin[6],
	   (unsigned char)in.bin[7],
	   (unsigned char)in.bin[8], 
	   (unsigned char)in.bin[9],
	   (unsigned char)in.bin[10],
	   (unsigned char)in.bin[11],
	   (unsigned char)in.bin[12],
	   (unsigned char)in.bin[13],
	   (unsigned char)in.bin[14],
	   (unsigned char)in.bin[15]);
}

/////////////////////////////////////////////////////////////////////////////
//
// Forward decl.
//

enum ReqType {GET, POST, PUT, PATCH, DELETE};

struct ApiResp;

struct DriveApi {
  ReqType      req_type;
  const char * path;
  const char * query;
  RootObject   params;
  FILE       * body_fh;
  FILE       * resp_fh;
  std::vector<const char *> headers;
  bool         include_headers;
  bool         raw_output; // Don't parse the output;
  bool         pre_auth;
  bool         hard_retry;
  ApiResp perform_noretry(bool reauthorize = true) const;
  ApiResp perform(bool reauthorize = true) const;
};

struct ApiResp {
  CURLcode curl_code;
  long http_code;
  string str;
  RootObject data;
  ApiResp()
    : curl_code(), http_code() {}
  ApiResp(ApiResp && other)
    : curl_code(other.curl_code), http_code(other.http_code),
      str(std::move(other.str)) {data = std::move(other.data);}
  ApiResp & operator=(ApiResp && other) {
    curl_code = other.curl_code;
    http_code = other.http_code;
    str = std::move(other.str);
    data = std::move(other.data);
    return *this;
  }
};
int report_error(const char * what, const ApiResp & resp);
#define HANDLE_ERROR(what, resp) if (report_error(what, resp) != 0) return -1;

void pre_init();

//////////////////////////////////////////////////////////////////////////////
//
// Authorization code
//

struct AuthData {
  char * access_token;
  char * header;
  char * refresh_token;
};

AuthData auth;

int get_auth_data() {
  {
    if (drive_auth[0] != '/') {
      char * path = realpath(drive_auth, NULL);
      if (!path && errno == ENOENT) return -1;
      if (!path) goto fail;
      drive_auth = path;
    }
    FILE * f = fopen(drive_auth, "r");
    if (!f) {
      if (errno == ENOENT) return -1;
      goto fail;
    }
    auth = {NULL, NULL, NULL};
    size_t sz = 0;
    auto res = getline(&auth.access_token, &sz, f);
    if (res <= 0) goto fail;
    if (auth.access_token[res-1] == '\n')
      auth.access_token[res-1] = '\0';
    res = getline(&auth.refresh_token, &sz, f);
    if (res <= 0) goto fail;
    if (auth.refresh_token[res-1] == '\n')
      auth.refresh_token[res-1] = '\0';
    asprintf((char **)&auth.header, "Authorization: Bearer %s", auth.access_token);
    fclose(f);
    return 0;
  }
 fail:
  fprintf(rlog, "ERROR: Could not read auth data from disk: %s\n", strerror(errno));
  exit(-1);
}

int put_auth_data(const char * access_token, const char * refresh_token) {
  {
    FILE * f = fopen(drive_auth, "w");
    if (!f) {goto fail;}
    auto res = fprintf(f, "%s\n%s\n", access_token, refresh_token);
    if (res == -1) goto fail;
    fclose(f);
    return 0;
  }
 fail:
  fprintf(rlog, "ERROR: Could not write auth data to disk: %s\n", strerror(errno));
  exit(-1);
}

int get_token(const char * code) {
  char data[1024];
  snprintf(data, 1024, "code=%s&client_id=%s&client_secret=%s&redirect_uri=urn:ietf:wg:oauth:2.0:oob&grant_type=authorization_code",
	   code, client_id, client_secret);
  DriveApi api = {POST, "oauth2/v4/token", data};
  api.pre_auth = true;
  auto resp = api.perform();
  HANDLE_ERROR("get_token", resp);
  auto access = resp.data["access_token"].GetString();
  auto refresh = resp.data["refresh_token"].GetString();
  put_auth_data(access, refresh);
  get_auth_data();
  return 0;
}

const char * get_code_url =
  "https://accounts.google.com/o/oauth2/v2/auth"
  "?response_type=code"
  "&client_id=%s"
  "&redirect_uri=urn:ietf:wg:oauth:2.0:oob"
  "&scope=%s";
void get_token() {
  printf("Please paste this into your browser and enter the code returned:\n ");
  printf(get_code_url, client_id, scope);
  printf("\n> ");
  fflush(stdout);
  char * code = NULL;
  size_t sz = 0;
  auto res = getline(&code, &sz, stdin);
  if (res <= 0) {
    printf("Sorry.  I could not get any input.");
    exit(-1);
  }
  if (code[res-1] == '\n')
    code[res-1] = '\0';
  res = get_token(code);
  if (res != 0) exit(-1);
}

int refresh_token() {
  fprintf(rlog, "*** Refresh Token\n");
  char data[1024];
  snprintf(data, 1024, "refresh_token=%s&client_id=%s&client_secret=%s&redirect_uri=urn:ietf:wg:oauth:2.0:oob&grant_type=refresh_token",
	   auth.refresh_token, client_id, client_secret);
  DriveApi api = {POST, "oauth2/v4/token", data};
  api.pre_auth = true;
  auto resp = api.perform();
  HANDLE_ERROR("refresh_token", resp);
  auto access = resp.data["access_token"].GetString();
  put_auth_data(access, auth.refresh_token);
  get_auth_data();
  return 0;
}

//////////////////////////////////////////////////////////////////////////////
//
// Curl and Drive API Helpers
//

pthread_mutex_t cache_lock = PTHREAD_ERRORCHECK_MUTEX_INITIALIZER_NP;
std::vector<CURL *> cached_conns;

struct CurlConn {
  CURL * conn;
  CurlConn(CURL * conn = NULL) : conn(conn) {}
  CurlConn(CurlConn && other) : conn(other.conn) {other.conn = NULL;}
  void clear() { 
    if (conn) {
      curl_easy_cleanup(conn);
      conn = NULL;
    }
  }
  CurlConn & operator=(CurlConn && other) {conn=other.conn; other.conn=NULL; return *this;}
  ~CurlConn() {
    if (conn) {
      curl_easy_reset(conn);
      pthread_mutex_lock(&cache_lock);
      cached_conns.push_back(conn);
      pthread_mutex_unlock(&cache_lock);
    }
  }
  operator CURL *() {return conn;}
};

CurlConn get_connection(const char * host) {
  pthread_mutex_lock(&cache_lock);
  if (cached_conns.empty()) {
    pthread_mutex_unlock(&cache_lock);
    auto conn = curl_easy_init();
    curl_easy_setopt(conn, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4);
    curl_easy_setopt(conn, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(conn, CURLOPT_TIMEOUT, 30);
    return conn;
  } else {
    auto conn = cached_conns.back();
    cached_conns.pop_back();
    pthread_mutex_unlock(&cache_lock);
    return conn;
  }
}

static size_t callback(const char* in, size_t size, size_t num, string * out) {
  auto totalBytes = size * num;
  out->append(in, totalBytes);
  return totalBytes;
}

static pthread_mutex_t rand_mutex = PTHREAD_ERRORCHECK_MUTEX_INITIALIZER_NP;
static int myrand() {
  pthread_mutex_lock(&rand_mutex);
  int val = rand();
  pthread_mutex_unlock(&rand_mutex);
  return val;
}
bool randfail = false;

ApiResp DriveApi::perform_noretry(bool reauthorize) const {
  ApiResp resp;
  auto conn = get_connection("www.googleapis.com");
  struct curl_slist *chunk = NULL;

  // Form URL
  char url[1024];
  const char * urlbase = "https://www.googleapis.com/";
  if (strncmp(path, "https://", 8) == 0) urlbase = "";
  if (query != NULL && (req_type == GET || body_fh != NULL || !params))
    snprintf(url, 1024, "%s%s?%s", urlbase, path, query);
  else
    snprintf(url, 1024, "%s%s", urlbase, path);
  curl_easy_setopt(conn, CURLOPT_URL, url);

  // Header special Request types
  switch (req_type) {
  case DELETE:
    // This is a dangerous operation that can not be undone.  Put it
    // first in the switch so that there is no possibility that some
    // other value for req_type will fallthrough to this code
    // and accidentally perform a delete.
    curl_easy_setopt(conn, CURLOPT_CUSTOMREQUEST, "DELETE"); 
    if (query || params || body_fh || resp_fh || include_headers || pre_auth) {
      fprintf(rlog, "Invalid parameters specified with DELETE verb.  Sorry, will crash now.");
      abort();
    }
    break;
  case PUT:
    curl_easy_setopt(conn, CURLOPT_UPLOAD, 1);
    chunk = curl_slist_append(chunk, "Expect: ");
    break;
  case PATCH: 
    curl_easy_setopt(conn, CURLOPT_CUSTOMREQUEST, "PATCH"); 
    break;
  default:;
    /* no special options needed */
  }

  // Add headers
  if (!pre_auth)
    chunk = curl_slist_append(chunk, auth.header);
  for (auto h : headers)
    chunk = curl_slist_append(chunk, h);

  // Register Body
  json::StringBuffer json_str;
  if (query && req_type != GET) {
    curl_easy_setopt(conn, CURLOPT_POSTFIELDS, query);
  } else if (params) {
    json::Writer<json::StringBuffer> writer(json_str);
    params.doc.Accept(writer);
    curl_easy_setopt(conn, CURLOPT_POSTFIELDS, json_str.GetString());
    chunk = curl_slist_append(chunk, "Content-Type: application/json");
    //fprintf(rlog, "%s\n", json_str.c_str());
  } else if (body_fh) {
    curl_easy_setopt(conn, CURLOPT_READDATA, body_fh);
  }

  // Misc Options
  curl_easy_setopt(conn, CURLOPT_ACCEPT_ENCODING, "");

  // Handle Responce
  bool parse_output = !raw_output;
  if (resp_fh) {
    curl_easy_setopt(conn, CURLOPT_WRITEDATA, resp_fh);
    parse_output = false;
  } else {
    curl_easy_setopt(conn, CURLOPT_WRITEDATA, &resp.str);
    curl_easy_setopt(conn, CURLOPT_WRITEFUNCTION, callback);
  }
  if (include_headers) {
    curl_easy_setopt(conn, CURLOPT_HEADER, 1);
    parse_output = false;
  }

  // Finish up and call perform
  curl_easy_setopt(conn, CURLOPT_HTTPHEADER, chunk);
  //curl_easy_setopt(conn, CURLOPT_HEADEROPT, CURLHEADER_SEPARATE);
  //curl_easy_setopt(conn, CURLOPT_VERBOSE, 1);

  if (randfail && myrand() < RAND_MAX/10) {
    fprintf(rlog, "error: random failure!\n");
    resp.curl_code = CURLE_COULDNT_CONNECT;
  } else {
    resp.curl_code = curl_easy_perform(conn);
  }

  curl_easy_getinfo (conn, CURLINFO_RESPONSE_CODE, &resp.http_code);

  if (resp_fh && (resp.curl_code != CURLE_OK || resp.http_code >= 300)) {
    // Reset file handle as any output from the failed http request
    // may have been written to the file
    fprintf(rlog, "oops. an error. truncating handle.\n");
    fflush(resp_fh);
    rewind(resp_fh);
    int fn = fileno(resp_fh);
    assert(fn >= 0);
    int res = ftruncate(fn, 0);
    if (res != 0) {
      fprintf(rlog, "error: truncate failed: %s\n", strerror(errno));
      return resp;
    }
  }
  if (resp.curl_code != CURLE_OK) {
    conn.clear();
    return resp;
  }
  // Try again if necessary
  if (resp.http_code == 401 && !pre_auth && reauthorize) {
    int ret = refresh_token();
    if (ret != 0) return resp;
    return perform(false);
  }
  if (resp.http_code >= 400)
    conn.clear();

  // Parse output if required
  if (parse_output && strspn(resp.str.c_str(), " \n\r") < resp.str.size()) {
    try {
      json::Document root;
      root.Parse(resp.str.c_str());
      resp.data = std::move(root);
    } catch (JsonException &) {}
  }

  return resp;
}

ApiResp DriveApi::perform(bool reauthorize) const {
  auto resp = perform_noretry(reauthorize);
  auto soft_retry = [&](int delay) {
    if (resp.http_code == 403) {
      fprintf(rlog, "got 403 retrying %d seconds.\n", delay);
      sleep(delay);
      resp = perform_noretry(reauthorize);
    }
  };
  soft_retry(1);
  soft_retry(2);
  soft_retry(5);

  if (this->hard_retry) {
    auto hard_retry = [&](int delay) {
      if (report_error("will retry...", resp) != 0) {
	sleep(delay);
	resp = perform_noretry(reauthorize);
      }
    };
    hard_retry(7);
    hard_retry(15);
    hard_retry(30);
    hard_retry(60);
    hard_retry(61);
    hard_retry(59);
  } 

  return resp;
}


int report_error(const char * what, const ApiResp & resp) {
  if (resp.curl_code != CURLE_OK) {
    fprintf(rlog, "CURL ERROR: %s: %s\n", what, curl_easy_strerror(resp.curl_code));
    return -2;
  }
  if (resp.http_code >= 300) {
    fprintf(rlog, "HTTP ERROR: %s: %ld\n%s\n", what, resp.http_code, resp.str.c_str());
    return -1;
  }
  return 0;
}

__attribute__ ((format (printf, 3, 4)))
void add_parm(string & res,
	      const char * key,
	      const char * fmt, ...) 
{
  va_list ap;
  va_start(ap, fmt);
  char val[1024];
  vsnprintf(val, 1024, fmt, ap);
  char * escaped = curl_easy_escape(NULL, val, 0);
  if (!res.empty()) res += '&';
  res += key;
  res += '=';
  res += escaped;
}

string get_http_header(const char * header, const char * text) {
  auto len = strlen(header);
  char to_find[len+4];
  to_find[0]='\n';
  memcpy(to_find + 1, header, len);
  strcpy(to_find + 1 + len, ": ");
  auto start = strstr(text, to_find);
  if (start == NULL) {
    fprintf(rlog, "Could not find %s\n", to_find);
    exit(-1);
  }
  start += len+3;
  auto stop = strchr(start, '\r');
  if (stop == NULL) abort();
  return string(start, stop);
};

//////////////////////////////////////////////////////////////////////////////
//
// Drive API Methods
//

string drive_mkdir(const char * name) {
  string query;
  add_parm(query, "q", "'root' in parents and name='%s' and trashed = false", name);
  auto resp = DriveApi{GET, "drive/v3/files", query.c_str()}.perform();

  if (resp.data["files"].Size() >= 1) {
    fprintf(rlog, "Folder \"%s\" already exists\n", name);
    exit(1);
  }

  DriveApi mkdir {POST, "drive/v3/files?fields=id"};
  mkdir.params.AddMember("name", StringRef(name));
  mkdir.params.AddMember("mimeType", "application/vnd.google-apps.folder");
  resp = mkdir.perform();
  report_error("mkdir", resp);

  //printf("Success\n");
  //printf("%s\n", resp.str.c_str());

  return resp.data["id"].GetString();
}

string find_folder(const char * name) {
  string query;
  add_parm(query, "q", "'root' in parents and name='%s' and trashed = false", name);
  auto resp = DriveApi{GET, "drive/v3/files", query.c_str()}.perform();

  //printf("Success\n");
  //printf("%s\n", resp.str.c_str());

  if (resp.data["files"].Size() != 1) {
    fprintf(rlog, "Folder \"%s\" not found or more than one found\n", name);
    exit(1);
  }
  return resp.data["files"][0]["id"].GetString();
}

RootArray ls_folder(const char * id, const char * q = NULL, const char * fields = NULL) {
  RootArray ret;
  string nextPageToken;

  do {
    string query;
    add_parm(query, "q", "'%s' in parents and %s", id, q ? q : "trashed = false");
    add_parm(query, "fields", "files(%s),kind,nextPageToken", fields ? fields : "id,kind,mimeType,md5Checksum,modifiedTime,name,size");
    if (!nextPageToken.empty()) 
      add_parm(query, "pageToken", "%s", nextPageToken.c_str());
    query += "&pageSize=1000";
    DriveApi ls{GET, "drive/v3/files", query.c_str()};
    ls.raw_output = false;
    auto resp = ls.perform();
    report_error("ls_folder", resp);

    json::Document data(&ret.doc.GetAllocator());
    data.Parse(resp.str.c_str());
    
    for (auto & v : data["files"].GetArray())
      ret.PushBack(v);
    
    nextPageToken = GetMember("nextPageToken", "", resp.data);
  } while (!nextPageToken.empty());

  return std::move(ret);
};

int upload_file(const char * from, const char * id, const char * to, char * new_id, size_t id_sz, CheckSum & md5) {
  fprintf(rlog, "uploading %s%s -> %s\n", id ? "id: " : "", id ? id : from, to);

  auto src = fopen(from, "r");

  if (!src) {
    fprintf(rlog, "ERROR: could not open \"%s\" for reading\n", from);
    return -1;
  }

  char url[1024];
  snprintf(url, 1024, "upload/drive/v3/files%s%s?uploadType=resumable&fields=name,id,size,md5Checksum",
	   id ? "/" : "", id ? id : "");

  DriveApi upload{id ? PATCH : POST, url};
  upload.headers.push_back("X-Upload-Content-Type: application/octet-stream");

  struct stat st = {};
  stat(from, &st);

  if (!id)
    upload.params.AddMember("parents", Value().SetArray().PushBack(StringRef(root_id), upload.params.doc.GetAllocator()));
  if (to)
    upload.params.AddMember("name", StringRef(to));
  char date[32];
  strftime(date, 32, "%Y-%m-%dT%TZ", gmtime(&st.st_mtime));
  upload.params.AddMember("modifiedTime", StringRef(date));

  upload.include_headers = true;

  auto resp = upload.perform();
  if (report_error("upload step 1", resp) != 0) {
    fclose(src);
    return -1;
  }

  //printf("Success\n");
  //printf("%s\n", resp.str.c_str());

  auto location = get_http_header("Location", resp.str.c_str());

  DriveApi put{PUT, location.c_str()};
  put.headers.push_back("Content-Type: application/octet-stream");
  put.body_fh = src;
  resp = put.perform();
  fclose(src);
  HANDLE_ERROR("upload step 2", resp);

  md5 = resp.data["md5Checksum"].GetString();
  
  //printf("Upload Success\n");
  //printf("%s\n", resp.str.c_str());
  
  ///return {resp.data["id"].asString(), atoi(resp.data["size"].asCString()), resp.data["md5Checksum"].asString()};

  if (new_id)
    strncpy(new_id, resp.data["id"].GetString(), id_sz);
 
  return 0;
}

int rename_file(const char * id, const char * to, time_t mtime) {
  fprintf(rlog, "renaming id:%s -> %s\n", id, to);
  char url[1024];
  snprintf(url, 1024, "drive/v3/files/%s?fields=name,id,size,md5Checksum", id);
  DriveApi rename{PATCH, url};
  rename.params.AddMember("name", StringRef(to));
  char date[32];
  strftime(date, 32, "%Y-%m-%dT%TZ", gmtime(&mtime));
  rename.params.AddMember("modifiedTime", StringRef(date));
  
  auto resp = rename.perform();
  HANDLE_ERROR("rename", resp);

  //printf("Rename Success!\n");
  //printf("%s\n", resp.str.c_str());

  return 0;
}

int trash_file(const char * id) {
  char url[1024];
  //snprintf(url, 1024, "drive/v3/files/%s?fields=name,id,size,md5Checksum", id); 
  snprintf(url, 1024, "drive/v3/files/%s", id);

  fprintf(rlog, "trashing id:%s\n", id);

  //DriveApi info{GET, url};
  //auto resp0 = info.perform();
  //HANDLE_ERROR("trash", resp0);
  //printf("Got gile info:\n");
  //printf("%s\n", resp0.str.c_str());
  
  DriveApi trash{PATCH, url};
  trash.params.AddMember("trashed", true);
  auto resp = trash.perform();
  HANDLE_ERROR("trash", resp);

  //printf("Trash Success!\n");
  //printf("%s\n", resp.str.c_str());

  return 0;
}

int delete_file(const char * id) {
  fprintf(rlog, "deleting id:%s\n", id);
  char url[1024];
  snprintf(url, 1024, "drive/v3/files/%s", id);
  DriveApi del{DELETE, url};
  auto resp = del.perform();
  HANDLE_ERROR("delete", resp);

  //printf("Delete Success!\n");
  //printf("%s\n", resp.str.c_str());

  return 0;
}

int empty_trash(const char * id) {
  randfail = false;
  rlog = stderr;
  auto to_del = ls_folder(id, "trashed = true", "id,name,trashed");
  if (to_del.Size() == 0) {
    printf("Trash is empty!\n");
    return 0;
  }
  printf("Are you sure you want to permanently remove %d files?\n", to_del.Size());
  char expect[64];
  snprintf(expect, 64, "YES DELETE %d FILES!", to_del.Size());
  printf("Please type \"%s\" to continue.\n> ", expect);
  fflush(stdout);
  char * resp = NULL;
  size_t resp_sz = 0;
  auto sz = getline(&resp, &resp_sz, stdin);
  if (resp != NULL && resp_sz > 1 && resp[sz-1] == '\n') resp[sz-1] = '\0';
  if (resp == NULL || strcmp(expect, resp) != 0) {
    printf("Sorry, Didn't get the responce I expected.  Aborting.\n");
    return -1;
  }
  for (auto & v : to_del) {
    if (!v["trashed"].GetBool()) {
      fprintf(rlog, "internal error: got back a file that was not trashed id=%s, name=%s\n", v["id"].GetString(), v["name"].GetString());
      return -1;
    }
    int res = delete_file(v["id"].GetString());
    if (res != 0) return res;
  }
  return 0;
}

int download_file(const char * id, const char * to) {
  fprintf(rlog, "downloading id:%s -> %s\n", id, to);
  auto src = fopen(to, "w");
  if (!src) {
    fprintf(rlog, "ERROR: could not open \"%s\" for writing\n", to);
    return -1;
  }

  char url[1024];
  snprintf(url, 1024, "drive/v3/files/%s?alt=media&fields=md", id);
  DriveApi download{GET, url};
  download.hard_retry = true;
  download.resp_fh = src;
  auto resp = download.perform();
  fclose(src);
  if (report_error("download", resp) != 0) {
    unlink(to);
    return -1;
  }

  return 0;
}

//////////////////////////////////////////////////////////////////////////////
//
// Remote API
//

void read_config() {
  auto f = fopen(".etc/drive.conf", "r");
  if (!f) {
    printf("Error: unable to read \".etc/drive.conf\".");
    exit(1);
  }
  try {
    char readBuffer[1024*16];
    json::FileReadStream is(f, readBuffer, sizeof(readBuffer));
    conf.ParseStream<json::kParseCommentsFlag>(is);
    fclose(f);
    
#define GET_CONF(key) {auto itr = conf.FindMember(#key); if (itr != conf.MemberEnd()) key = itr->value.GetString();}
    GET_CONF(remote_dir);
    if (remote_dir == NULL) {
      printf("Error: 'remote_dir' conf option required\n");
      exit(1);
    }
    GET_CONF(client_id);
    GET_CONF(client_secret);
    GET_CONF(redirect);
    GET_CONF(scope);
    GET_CONF(drive_auth);
    use_delete = GetMember("use_delete", use_delete, conf);
#undef GET_CONF
  } catch (JsonException & err) {
    fprintf(stderr, "ERROR: %s: ", ".etc/drive.conf");
    fprintf(stderr, "%s\n", err.what());
    exit(1);
  }
}

int init(const char * datadir, RemoteState *) {
  assert(strcmp(datadir, ".") == 0);
  
  read_config();

  pre_init();
  auto res = get_auth_data();
  if (res == -1) {get_token();}

  string query;
  add_parm(query, "q", "'root' in parents and name='%s' and trashed = false", remote_dir);
  auto resp = DriveApi{GET, "drive/v3/files", query.c_str()}.perform();
  report_error("find dir", resp);
  
  if (resp.data["files"].Size() == 0) {
    root_id = drive_mkdir(remote_dir);
  } else if (resp.data["files"].Size() == 1) {
    root_id = resp.data["files"][0]["id"].GetString();    
  } else if (resp.data["files"].Size() > 1) {
    fprintf(rlog, "Found more than one folder: %s", remote_dir);
    exit(1);
  } else {
    abort(); 
  }

  rlog = fopen(".var/drive.log", "a");
  if (rlog == NULL) {
    perror("remote logfile");
    exit(EXIT_FAILURE);
  }
  setvbuf(rlog, NULL, _IOLBF, 0);

  auto t = time(NULL);
  auto tm = localtime(&t);
  char datestr[64];
  strftime(datestr, 64, "%F %T %Z", tm);
  
  fprintf(rlog, "statup time = %s\n", datestr);
  fprintf(rlog, "root folder id = %s\n", root_id.c_str());
  return 0;
}

int kill(RemoteState *) {
  return 0;
}

int list(RemoteState *, RemoteOpsListCallback cb, void * data) {
  auto res = ls_folder(root_id.c_str());
  for (auto & fi : res) {
    // FIXME: Disallow folders and other google docs objects
    const char * id = fi["id"].GetString();
    const char * path = fi["name"].GetString();
    size_t size = atoi(fi["size"].GetString());
    //printf("??>%s %s %u\n", fi["name"].asCString(), fi["size"].asCString(), size);
    struct tm tm = {};
    /*char * res =*/ strptime(fi["modifiedTime"].GetString(), "%Y-%m-%dT%T", &tm);
    time_t mtime = timegm(&tm);    
    CheckSum md5 = fi["md5Checksum"].GetString();
    cb(data, id, path, size, mtime, &md5);
  }
  return 0;
}

int checksum(RemoteState *, const char * path, CheckSum * checksum) {
  int src = open(path, O_RDONLY);
  if (src < 0) {
    fprintf(rlog, "ERROR: could not open \"%s\" for reading: %s\n", path, strerror(errno));
    return -1;
  }
  ComputeMD5 md5c;
  static const unsigned buf_sz = 1024*8;
  char buf[buf_sz];
  ssize_t sz;
  while (sz = read(src, buf, buf_sz), sz > 0) {
    md5c.add(buf, sz);
  }
  md5_bin_to_hex(md5c.output(), *checksum);
  close(src);
  return 0;
}


int download(RemoteState *, const char * id, const char * to) {
  return download_file(id, to);
}

int upload_new(RemoteState *, const char * from, const char * to, char * id, size_t id_sz, CheckSum * checksum) {
  return upload_file(from, NULL, to, id, id_sz, *checksum);
}

int replace(RemoteState *, const char * from, const char * id,  CheckSum * checksum) {
  return upload_file(from, id, NULL, NULL, 0, *checksum);
}

int rename(RemoteState *, const char * from, const char * to, time_t mtime) {
  return rename_file(from, to, mtime);
}

int del(RemoteState *, const char * path) {
  if (use_delete)
    return delete_file(path);
  else
    return trash_file(path);
}

int empty_trash(RemoteState *) {
  return empty_trash(root_id.c_str());
}

RemoteOps drive_remote {
  init, kill, list, checksum, download, upload_new, replace, rename, del, empty_trash
};

//////////////////////////////////////////////////////////////////////////////
//
// Main for testing
//

#if 0
int main() {

  pre_init();

  auto res = get_auth_data();
  if (res == -1) {get_token();}
  drive_mkdir("testme");
  root_id = find_folder("testme");
  printf("folder id = %s\n", root_id.c_str());
  ls_folder(root_id.c_str());
  auto fi = upload_file("./drive.cpp", NULL, "/fullpath/drive.cpp");
  printf("Renaming\n");
  rename_file(fi.id.c_str(), "/otherpath/drive.cpp");
  upload_file("./zbfs.cpp", fi.id.c_str(), NULL);
  upload_file("./zbfs.cpp", NULL, "tmp/tmp");
  download_file(fi.id.c_str(), "somefile.txt");
  trash_file(fi.id.c_str());
  ls_folder(root_id.c_str());
  delete_file(fi.id.c_str());
  delete_file(root_id.c_str());
  return 0;
}

#endif

