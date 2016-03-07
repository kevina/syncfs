--
-- Main tables
--
create table if not exists fileinfo (
  fid integer not null primary key, /* an abstract inode */
  dir text, /* full path of dir */
  name text /* file name */,
  writable boolean,
  local boolean, /* stored locally */
  atime int,
  mtime int,
  opened int not null default(0), /* 0: Closed, 1: OpenedRO, 2: OpenedRW */
  open_count int not null default(0),
  cid integer, /* not defined when opened == OpenedRW */
  keep_local bool default (0),
  remote_cid integer, /* null = not uploaded yet */
  remote_id string, 
  remote_path text,
  remote_failures int default (0), /* used for prioritizing */
  downloading boolean default (0), 
  unique(dir,name), 
  unique(remote_path) 
);
create table if not exists contentinfo (
  cid integer not null primary key, /* content id */
  checksum text,
  size int
);
create table if not exists in_progress (
  fid integer not null primary key, 
  action string, 
  new_cid integer, 
  new_path integer 
);
-- for debugging to make sure we don't get fid and cid mixed up
-- new values for cid will now start at 10001
insert or ignore into contentinfo (cid) values (10000);

--
-- Views used by the background tasks
--
drop view if exists want_to_remove;
create view want_to_remove as
  select fid,dir||name as path,atime,mtime,size,coalesce(cid = remote_cid,0) as may_remove from fileinfo join contentinfo using (cid)
  where local and opened=0 and not keep_local;
drop view if exists pending;
create view pending as
  select fid,
    dir is null and remote_path is not null as to_delete,
    dir is not null and checksum is not null and (remote_cid is null or cid != remote_cid) as to_upload,
    coalesce(dir||name != remote_path,0) as to_rename,
    (select fid from fileinfo where fid != f.fid and f.dir||f.name = remote_path) as blocked_by,
    size,
    case when dir is null then 0 else size end - case when remote_path is null then 0 else r_size end as size_delta
  from fileinfo f left join contentinfo using (cid) left join (select cid as remote_cid, size as r_size from contentinfo) using (remote_cid);

--
-- Tables used for syncing
--
drop table if exists local;
create table local (
  dir text, name text, size int, atime int, mtime int
);
drop table if exists remote;
create table remote ( 
  id text, path text, size int, mtime int, checksum text
);

--
-- Other useful views
--
create temporary view remote_only as select * from remote where path not in (select remote_path from fileinfo where remote_path is not null); 
create temporary view remote_diff as 
  select fid,cid, path, r.path is not null as in_remote, (r.size != f.size or r.checksum != f.checksum) as diff, r.mtime as r_mtime, f.mtime as f_mtime  
  from (select fid,cid,remote_path as path, size, mtime, local, checksum from fileinfo join contentinfo using (cid) where remote_path is not null) as f 
  left join remote as r using (path) 
  where r.mtime != f.mtime or r.size != f.size or r.path is null;
