#!/bin/sh
VERIFIED=/tmp/.adb_auth_verified

if [ -f "$VERIFIED" ]; then
    echo "success."
    exit
fi

for i in $(seq 1 3); do
    read -p "$(hostname -s)'s password: " PASSWD
    if [ "$(echo $PASSWD | md5sum)" = "24f192481770c0978c713cf2d41394e6  -" ]; then
        echo "success."
        touch $VERIFIED
        exit
    fi

    echo "password incorrect!"
done

false
