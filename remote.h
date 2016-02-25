#include <sys/types.h>
#include <string.h>

// enum { // Return values
//   R_SUCCESS = 0,
//   R_NOEFFECT = -1, // delete or rename failure becuase file does not exist
//   R_RATE_LIMIT = -2, // rate limit
//   R_CONN_FAIL = -3, // connection problem
//   R_FAIL = -4, // other storage failure
// };

// /* Error actions:
//   On R_NOEFFECT // log and continue
//      R_RATE_LIMIT // use exponential backup stating with 0.5 sec
//      R_CONN_FAIL // use exponential backup stating with 15 seconds
//      R_FAIL // log and try again on next round
// */

// download a file and store it in the correct location 
// return 0 on success

// note: an internal copy of the strings is made

#define CHECKSUM_SZ (128/4 + 1)
typedef struct CheckSum {
  // a 128 bit value in hex
  char hex[CHECKSUM_SZ];
#ifdef __cplusplus
  bool empty() const {return hex[0] == '\0';}
  explicit operator bool() const {return hex[0] != '\0';}
  CheckSum() : hex() {}
  CheckSum(const char * str) {
    strncpy(hex, str, CHECKSUM_SZ);
    hex[CHECKSUM_SZ-1] = '\0';
  }
  CheckSum & operator=(const char * str) {
    strncpy(hex, str, CHECKSUM_SZ);
    hex[CHECKSUM_SZ-1] = '\0';
    return *this;
  }
#endif
} CheckSum;

#ifdef __cplusplus
static inline bool operator==(const CheckSum & x, const CheckSum & y) {
  return memcmp(x.hex, y.hex, CHECKSUM_SZ-1) == 0;
}
static inline bool operator!=(const CheckSum & x, const CheckSum & y) {
  return memcmp(x.hex, y.hex, CHECKSUM_SZ-1) != 0;
}
#endif 

typedef struct RemoteState {
  void * data;
} RemoteState;

typedef void (*RemoteOpsListCallback)(void *, const char * id, const char * path, int size, time_t mtime, const CheckSum *);

typedef struct RemoteOps {
  // Init the remote
  // The first argument is the path to the data dir.
  // May get additional information from the terminal
  int (*init)(const char *, RemoteState *);
  // Kill the remote
  int (*kill)(RemoteState *);

  // Get a listing of all paths on the remote
  int (*list)(RemoteState *, RemoteOpsListCallback cb, void * cb_data);

  // If the download fails than an IO error will be returned to the
  // client so the remote should retry on transient errors.
  //
  // upload, rename, and delete are only called by the uploader
  // background task.  On transient errors it is acceptable to return.
  // However, the remote should do it's own rate limiting as each
  // error causes a 5 second or more delay before the next attempt.

  // compute the checksum of the file using the same algorithm that the
  // server will use
  int (*checksum)(RemoteState *, const char * path, CheckSum *);

  // Download a file.
  //
  // If the remote uses seperate internal ids for file, from will be
  // an id, otherwise it will be the last known path name.
  int (*download)(RemoteState *, const char * from, const char * to);

  // When uploading it is the remotes responsibility to set the mtime
  // of "to" so it matches "from".  If this is not possible than
  // the remote may adjust the mtime of "from".  In all cases
  // the mtime of from and to must match.

  // Uploads a new file, if the remote uses internal ids than the id
  // should be copied into id using no more than id_sz bytes.
  //
  // If the remote supports some sort of CheckSum then store it in
  // checksum.
  int (*upload_new)(RemoteState *, const char * from, const char * to, 
		    char * id, size_t id_sz, CheckSum * checksum);

  // Upload and replace a path. If "to" will be an internal id if the
  // remote uses it.
  int (*replace)(RemoteState *, const char * from, const char * to, CheckSum * checksum);

  // Rename a path, "from" will be an internal id if the remote uses
  // it.  mtime is the original modification of the file, if the remote
  // changes changed the mod. time of a file when renaming use this
  // parameter to reset it back to what it should be
  int (*rename)(RemoteState *, const char * from, const char * to, time_t mtime);

  // Delete a path, "path" will be an intenral if the remote uses it.
  int (*del)(RemoteState *, const char * path);

  // Remove all trashed files within the configured directory
  // Should prompt the user for confirmation
  int (*empty_trash)(RemoteState *);
} RemoteOps;

extern RemoteOps file_remote;
extern RemoteOps drive_remote;
