#!/bin/bash
chmod +w $1
otool -L $1 | awk -v DST=$1 '/libssl|libcrypto/ {cmd = "install_name_tool -change " $1 " @loader_path" substr($1, match($1, "/[^/]+$")) " " DST; print cmd; system(cmd)}'
