#!/bin/sh

#
# This is the script I use internally test SyncFS with zbackup.
#

set -e
set -x

cp data/.etc/syncfs.conf.for-backup data/.etc/syncfs.conf

fusermount -uz ./backup || true
sleep 1
./syncfs data backup

rm -f backup/info
rm -rf backup/bundles
rm -rf backup/backups
rm -rf backup/index
rm -rf backup/tmp
sleep 2

../zbackup --non-encrypted init backup/

cat to-backup-1 | ../zbackup --non-encrypted backup backup/backups/backup-1
sleep 2

cat to-backup-2 | ../zbackup --non-encrypted backup backup/backups/backup-2
sleep 2

../zbackup --non-encrypted restore backup/backups/backup-2 > /dev/null

cat to-backup-3 | ../zbackup --non-encrypted backup backup/backups/backup-3
rm backup/backups/backup-1
../zbackup --non-encrypted gc fast backup
rm backup/backups/backup-2
../zbackup --non-encrypted gc fast backup

../zbackup --non-encrypted restore backup/backups/backup-3 > backup-3-res
cmp to-backup-3 backup-3-res
sleep 3

../zbackup --non-encrypted gc deep backup

while pending=`cat /aux/backup/k/backup/.proc/pending`
      test -n "$pending"
do echo "SyncFS Still Busy..."
   sleep 5
done

fusermount -u ./backup
sleep 1
rm -r data/*

./syncfs data backup

../zbackup --non-encrypted restore backup/backups/backup-3 > backup-3-res
cmp to-backup-3 backup-3-res

while pending=`cat /aux/backup/k/backup/.proc/pending`
      test -n "$pending"
do echo "SyncFS Still Busy..."
   sleep 5
done

fusermount -u ./backup
rm -r data/*

rm data/.var/fileinfo.db
./syncfs data backup

../zbackup --non-encrypted restore backup/backups/backup-3 > backup-3-res
cmp to-backup-3 backup-3-res

sleep 7

if [ -n "`find data/bundles -type f`" ]
then
  echo "ERROR: data/bundles not removed locally when it should be"
  fusermount -u ./backup
  exit 1
fi

# 90 seconds is the default delete time unless otherwise specified
sleep 100

if [ ! \( -e data/info -o -e data/backups/backup-3 \) ]
then
  echo "ERROR: data/info or other file removed locally when it should be kept"
  fusermount -u ./backup
  exit 1
fi

fusermount -u ./backup

sleep 1;

echo "TESTING SYNC TO REMOTE"

cp data/.etc/syncfs.conf.keep-all data/.etc/syncfs.conf

./syncfs data backup

find backup/* -type f | xargs cat > /dev/null

fusermount -u ./backup

rm data/index/*
echo ' junk' >> data/backups/backup-3 
echo 'content' > data/backups/afile.txt

./syncfs --sync-to-remote-for-real data backup

sleep 5
while pending=`cat /aux/backup/k/backup/.proc/pending`
      test -n "$pending"
do echo "SyncFS Still Busy..."
   sleep 5
done

fusermount -u ./backup

./syncfs data backup

sleep 1

fusermount -u ./backup

echo "ALL TEST PASS"
