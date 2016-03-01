# Introduction

**SyncFS** is a [Filesystem in Userspace (FUSE)][FUSE] that offers
something between mounting a cloud storage system using FUSE while
keeping all changes remotely, and syncing a Cloud drive locally.  It
was original designed to provide a cloud storage backend to [ZBackup].

[FUSE]: https://github.com/libfuse/libfuse
[ZBackup]: http://zbackup.org/

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

  * Supports [Google Drive] as a remote.  Other remotes should be easy
    to add.

  * Uses an [sqlite3] database with a simple schema for all state.

[Google Drive]: https://www.google.com/drive/
[sqlite3]: https://www.sqlite.org/

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
  * `sqlite3-dev` (https://www.sqlite.org/)
  * `libcurl4-dev-openssl` or `libcurl4-dev-gnutls` (https://curl.haxx.se/libcurl/)
  * `libfuse-dev` (https://github.com/libfuse/libfuse)

To build edit the `Makefile` for your system and then just:

```bash
make
```

There is no install target.

# Quick Start

To test SyncFS using the sample config files do the following.  This
will create the folder `syncfs-storage` in your Google Drive account.

```bash
mkdir data
mkdir data/.etc
cp doc/syncfs.conf data/.etc
cp doc/drive.conf data/.etc
mkdir mnt
./syncfs data mnt
```

Then follow the instructions to give SyncFS authorization to your
Google Drive account.  (It can be done on a headless server.)

Any changes you make in mnt/ will then be uploaded to the
`syncfs-storage` folder on Drive.  With the default config it will
wait 30 seconds before uploading.  Then in the file is not used for 90
seconds it will delete it locally and redownload it when required.

To disconnect use:

```base
fusermount -u mnt
```

# Usage

## Startup

To use create a directory `.etc/` inside the directory you want to
sync with add create two configuration files `.etc/syncfs.conf` and
`.etc/drive.conf`.  Sample configuration files can be found in the
`doc/` directory.  The remote to use must be set in `.etc/syncfs.con`
and the REMOTEDIR to use must be set in `.etc/drive.conf`, all other
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

## Shutdown 

To shutdown SyncFS just unmount the filesystem using fusermount:

```
fusermount -u LOCALDIR
```

Note, that SyncFS may shutdown even if there are remote operations in
the queue.  To verify everything is in sync check that the virtual
file `.proc/pending` has no content.  Like files in the /proc
filesystem, the reported size is always zero; you need to open and
read the verify there is no content.  The actual content of this file
are not stable but will give you some idea of what operations are
pending.  If SyncFS does not look like it is making any progress than
there could be a problem connecting to the server, see the
`.etc/drive.log` file to verify.

Note, that if SyncFS shuts down (or is killed) with pending operations
those operations will simply resume once SyncFS restarts.

## Emptying the Trash

By default SyncFS will use the remote ability to move files to the
trash instead of deleting them.  This can either be cleaned up
manually using the Remote GUI if it has one or automatically using the `--empty-trash` option.

```bash
syncfs --empty-trash LOCALDIR MOUNTPOINT
```

SyncFS will ask for confirmation before it proceeds and then
permanently delete all trashed files in REMOTEDIR.  On some remotes
that this can take awhile.

# State and log files

SyncFS stores all its state in a sqlite3 database file named
`.var/fileinfo.db` under LOCALDIR that is also visable as a read-only
file under the MOUNTPOINT.  You are free to query the database to
learn about how SyncFS works or to get state information not easilly
available otherwise but do not perform any modications or hold a lock
on the database file for any length of time.

SyncFS writes to two log files `.var/syncfs.log` and `.var/drive.log`.
These files can safely be truncated if they get too large.

# Status

SyncFS is considered to be of Alpha qualify.  When used with zbackup I
trust it enough to use it to backup my data on a VPS.  It us unlikely
that it will destroy any of your data, but it might do odd things.

# Upgrading

As SyncFS is Alpha software the database schema may change at any
time.  As the database serves as a cache the cleanest way to upgrade
is to use the old version to make sure there are no pending
operations (`.proc/pending` is empty) and then (after unmounting the
filesystem) use the `--reset-db` option with the new version.  If this
is done before all pending operations are clear than SyncFS might
report discrepancies that need to be manually fixed before it will
start.

# Adding Additional Remotes

I will be happy to accept pull requests that add additional remotes
(such as Amazon S3, or sftp).  I will likely reject the request,
however, if it brings in any unneeded dependencies.

# Feedback

Please email me directly at k@kevina.org or use the GitHub issue tracker.

