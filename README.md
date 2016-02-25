# Introduction

**SyncFS** is a Filesystem in Userspace (FUSE) that offers something
between mounting a cloud storage system as a fuse filesystem while
keeping all changes remotely and syncing a remote Clouse storage
system and keeping the files locally.  It was original designed to
provide a cloud storage backend to ZBackup.

It works by mirroring the files on the cloud (the remote) to the local
filesystem, but only keeping the files local that are currently in
use.  If a file is opened that is not stored locally it will be
downloaded to the local filesystem before the open system call
returns.  From that point on all filesystem operations are done
locally.  When the file is closed any changes will be uploaded to the
cloud and the file will eventually be removed locally when it is no
longer needed.

The policy of when to keep a file locally and how long to wait until a
file is uploaded can be configued on a per-file or per-directory
basis.

# Features

  * Fast metadata access and modifications.  The complete directory
    listing of the remote is kept locally.  Any modifications to the
    metadata (including renames) are done locally and then the request
    are queued to be sent to the remote.  Multiple metadata
    modifications may be made to the same file without having to wait
    for the remote to get in sync.

  * Fast Writes.  All modifications to a file are done locally.  Once
    closed the file is queued to be uploaded.  If the file is modified
    again before the upload starts, the upload is canceled until the
    file is closed again.

  * Verifies the integrity of all uploades and downloads using the the
    checksum provided by the remote.

  * Supportes Google Drive as a remote.  Other remotes should be easy
    to add.

  * Uses an sqlite3 database with a simple schema for all state.

# Major Limitations

  * SyncFS has no concept of directories on the remote.  It will store
    everything in a single folder and the directory will become part
    of the filename.

  * There is no support for symbolic or hard links and only basis file
    system operations are supported for now.

  * To keep the remote from doing anything fancy with the file all
    files are uploaded with the "application/octet-stream" MIME type.

  * Two way sync is not supported.  It is assumed that the files on
    the remote will not change while the filesystem is mounted.  On
    startup SyncFS will check if either the local filesystem or the
    remote filesystem is out of sync with its internal state and will
    refuse to start until the situation is resolved.

# Installing

SyncFS was devloped on UBuntu 12.04 and has the following dependencies:

  * Recent enough version of Gcc or Clang to support most of C++11.
    (Gcc 4.6.3 is known to work.)
  * Unix like operating system with FUSE support
  * `sqlite3-dev`
  * `libcurl4-dev-openssl` or `libcurl4-dev-gnutls`
  * `libfuse-dev`

To build edit the `Makefile` for your system and then just:

```bash
make
```

There is no install target.

# Usage

## Startup

To use create a directory `.etc/` inside the directory you want to
sync with add create two configuration files ".etc/syncfs.conf" and
".etc/drive.conf".  Sample configuration files can be found in the
`doc/` directory.  The remote to use must be set in ".etc/syncfs.conf"
and the REMOTEDIR to use must be set in ".etc/drive.conf", all other
settings are optional.

Once this is done start syncfs using:

```bash
syncfs LOCALDIR MOUNTPOINT
```

SyncFS will give you a web page to visit to authorize it to access
your Google Drive account, visit it and copy and paste the access
code.

If the REMOTEDIR does not exist it will be created and populated with
the contents of LOCALDIR.  If REMOTEDIR is not empty it will be used
to populate the internal state and then verify the state is consistent
with what is in LOCALDIR.  If there is an inconsistency it will abort.

If this is not the first time SyncFS started with LOCALDIR it will
check that its internal state is consistent with what is in both
LOCALDIR and REMOTEDIR and will abort if its finds any
inconsistencies.  To help is resolve the situation you can can either
instruct SyncFS to throwaway any changes on in LOCALDIR and sync from
REMOTEDIR or the other way around.  To sync REMOTEDIR to LOCALDIR
(i.e., throw away local changes) use:

```bash
syncfs --sync-to-local-noop LOCALDIR MOUNTPOINT
```

to first check for any destructive operations that will be performed
(non-destructive operations such as adding a new file will not be
reported) and then use:

```bash
syncfs --sync-to-local-for-real LOCALDIR MOUNTPOINT
```

to do the sync.

To do the reverse (sync from LOCALDIR to REMOTEDIR use)
`--sync-to-remote-noop` and `--sync-t-remote-for-real` instead.

To throw away any local state (for example if the database state has
become corruped) you can use `--reset-db` to try and repopulate the
database as from the contents of REMOTEDIR and LOCALDIR.  If after
doing so they are any inconsistencies it will abort until they are
fixed by using `--sync-to-local` or `sync-to-remote` or some other
means.

# Shutdown 

To shutdown SyncFS just unmount the filesystem using fusermount:

```
fusermount -u LOCALDIR
```

Note, that SyncFS may shutdown even if there are remote operations in
the queue.  To verify everything is in sync check that the virtual
file ".proc/pending" has no content.  Like files in the /proc
filesystem, the reported size is always zero; you need to open and
read the verify there is no content.  The actual content of this file
are not stable but will give you some idea of what operations are
pending.  If SyncFS does not look like it is making any progress than
there could be a problem connecting to the server, see the
.etc/drive.log file to verify.

Note, that is SyncFS shuts down (or is killed) with pending operations
those operations will simply resume once SyncFS restarts.

# State and log files

SyncFS stores all its state in a sqlite3 database file named
".var/fileinfo.db" under LOCALDIR that is also visable as a read-only
file under the MOUNTPOINT.  You are free to query the database to
learn about how SyncFS works or to get state information not easilly
available otherwise but do not perform any modications or hold a lock
on the database file for any length of time.

SyncFS writes to two log files ".var/syncfs.log" and ".var/drive.log".
These files can safely be truncated if they get too large.

# Emptying the Trash

By default SyncFS will use the remote ability to move files to the
trash instead of deleting them.  This can either be cleaned up
manually using the Remote GUI if it has one or automatically using the `--empty-trash` option.

```bash
syncfs --empty-trash LOCALDIR MOUNTPOINT
```

SyncFS will ask for confirmation before it proceeds and then
permanently delete all trashed files in REMOTEDIR.  On some remotes
that this can take awhile.




