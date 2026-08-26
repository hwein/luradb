#!/bin/sh
# Replaces, inside the container, what systemd handles on the target system:
# StateDirectory=/RuntimeDirectory=/WorkingDirectory= and starting as user luradb.
set -e

CONFIG=/etc/luradb/luradb.toml

install -d -o luradb -g luradb -m 0750 /var/lib/luradb /run/luradb

# The Dockerfile restores the placeholder that postinst set during the image
# build, so the live key is generated here instead of baked into a layer.
# Idempotent like postinst: a populated etc volume (second start onward) has
# no placeholder left, so this is a no-op and nothing is re-logged.
if grep -q '@GENERATED_ON_INSTALL@' "$CONFIG"; then
    key="${LURADB_ADMIN_KEY:-lura_$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')}"
    sed -i "s/@GENERATED_ON_INSTALL@/$key/" "$CONFIG"
    echo "luradb: generated admin api key: $key"
fi

cd /var/lib/luradb

exec setpriv --reuid luradb --regid luradb --clear-groups \
    /usr/bin/luradb --config /etc/luradb/luradb.toml
