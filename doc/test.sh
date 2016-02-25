#!/bin/sh

#
# This is the script I used to test SyncFS with zbackup.
#

set -e
set -x

fusermount -uz ./backup
sleep 1
./zbfs data backup 

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

./zbfs data backup

../zbackup --non-encrypted restore backup/backups/backup-3 > backup-3-res
cmp to-backup-3 backup-3-res
