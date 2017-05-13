#! /bin/sh

if [ "$1" = "--unbound" ]; then
    # make a backup of crontab (only readable by this user)
    OLD_UMASK=`umask`
    umask 077
    crontab -l > /tmp/crontab-backup.$USER.$$
    umask $OLD_UMASK
    # add our key tag to the crontab
    (crontab -l; 
     echo "# key tag query (added by crontag.sh)";
     awk 'BEGIN { printf("@daily ") }';
     awk -f mkdtemp.awk -f unboundtag.awk) | crontab
else
    echo "Syntax: $0 --unbound" >&2
    exit 1
fi

