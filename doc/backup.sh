#!/bin/sh

#
# This is the script I use to backup my 13G mail partition that
# compresses to around 5 GB.
#
# It needs to run as root.
#

set -e
set -x

umount -l backup-mnt || true
lvremove -f /dev/lvm/mail-backup || true

sleep 2

sudo -u kevina ./syncfs backup-local backup-mnt

lvcreate -L1G -s -n mail-backup /dev/lvm/mail

DATE=`date +'%Y.%m.%d_%H'`

sudo -u kevina rm backup-mnt/tmp/* || true

/opt/e2fsprogs/sbin/e2image -rap /dev/lvm/mail-backup -  | sudo -u kevina ./zbackup --password-file password backup backup-mnt/backups/mail-$DATE

sleep 30

lvremove -f /dev/lvm/mail-backup

while pending=`sudo -u kevina cat backup-mnt/.proc/pending`
      test -n "$pending"
do echo "SyncFS Still Busy..."
   sleep 5
done

umount -l backup-mnt
