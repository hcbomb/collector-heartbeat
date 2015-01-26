#!/bin/sh

file=$1
body=
email=<email>

for i in $(tail -n +2 $file | cut -d, -f2); do
  nc -w0 -u $i 514 <<< "<46>$(date +'%m-%d-%YT%H:%M:%S') $(hostname) COLLECTOR HEARTBEAT TEST"
  ret=$?

  if [ "$ret" -ne "0" ]; then
    body="$body\nfailed: $i"
  fi
done

if [ -n "$body" ]; then
  echo -e "$body" | mail -s "Validate: IT log collectors down" $email
fi
