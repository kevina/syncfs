Note: This document described the internals as of version 0.001.  It
is now already out of data.  As SyncFS is alpha software the internal
workings will likely change many times.  The Sqlite3 schema is now in
the file `synfs.sql`.

# Schema

SyncFS uses an sqlite3 database to store all of its internal state.
It uses a simple schema with two tables, `fileinfo` and `contentinfo`.
The `fileinfo` table represents the filesystem; it's primary key is
`fid` that serves as an inode.  The `contentinfo` table represents the
content of a file at a particular point in time; It's primary key is
`cid` that stands for content-id.  The schema for the two tables are
as follows:

```sql
create table fileinfo (
  fid integer not null primary key,
  dir text, /* full path of dir */
  name text /* file name */,
  /* various other fields for file-metadata such as size */
  cid integer,
  local boolean, /* stored locally */"
  /* various other fields for internal state */
)

create table contentinfo (
  cid integer not null primary key,
  fid integer,
  checksum text,
  remote_path text,
)
```

When a file is opened for writing it does not have any content-id
associated with it.  Once it is closed a new entry in the
`contentinfo` and linked to the corresponding `fileinfo` entry.

# Semantics

All local operations only change fileinfo.

* When a new file is created a new fileinfo entry is created with a null
cid.  After is is closed a background thread will create a new `cid`
for the file.

* When a file is deleted the dir and name fields become null.

* When a file is renamed the dir or name simply change.

* When a file is opened for writing the `cid` becomes null.  When it
  is closed a new `cid` is created by the background thread shortly
  after closing the file.

The `local` field determines if a file is stored locally, if not it
will need to be downloaded when opened.

The `contentinfo` table determines the state of a file on the remote.
If `remote_path` is null then the file does not exist yet on the
remote.  If it is not null that then `remote_path` indicates the full
path of the file on the remote.

All remote operations (except downloading) are performed by a
background uploader thread.  It determines what needs to be done to
get the remote in sync based on the combined state of the `fileinfo`
and `contentinfo` tables.

Before anything first create contentinfo entries for any fileinfo
entries that don't correspond to an file currently opened for writing.
Then:

* If `remote_path` is null and `dir` (from fileinfo) is not null than
  the file needs to be uploaded to the remote.

* If `remote_path` is not null and `dir` is null than the file needs
  to be deleted on the remote.

* If `remote_path` does not equal the local path (the combined `dir`
  and `file` fields) than the file needs to be renamed.

And that is it.  Assuming nothing changes on the remote side, this
simple logic is enough to keep the state straight on both the local
and remote.








