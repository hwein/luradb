#!/bin/sh
# Replaces, inside the container, what systemd handles on the target system:
# StateDirectory=/RuntimeDirectory=/WorkingDirectory= and starting as user luradb.
set -e

install -d -o luradb -g luradb -m 0750 /var/lib/luradb /run/luradb
cd /var/lib/luradb

exec setpriv --reuid luradb --regid luradb --clear-groups \
    /usr/bin/luradb --config /etc/luradb/luradb.toml
