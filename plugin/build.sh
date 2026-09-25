#!/bin/sh
# Compile the on/off plugin against MariaDB 11.4 server headers.
# The HTTP daemon stays a separate process.
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
inc=${MARIA_NET_PLUGIN_INCLUDE:-/usr/include/mariadb/server}
out=${1:-"$root/plugin/maria_net.so"}
gcc -shared -fPIC -O2 -DMYSQL_DYNAMIC_PLUGIN -I"$inc" -o "$out" "$root/plugin/maria_net.c"
echo "$out"
