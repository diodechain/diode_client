#!/bin/bash
SUDO=`which sudo`
read -r -d '' PATCH <<'EOF'
diff --git src/runtime/runtime.go src/runtime/runtime.go
index 33ecc260dd..dea79f6095 100644
--- src/runtime/runtime.go
+++ src/runtime/runtime.go
***************
*** 14,19 ****
--- 14,25 ----
  //go:generate go run mkfastlog2table.go
  //go:generate go run mklockrank.go -o lockrank.go
  
+ // GetGoID returns the goid
+ func GetGoID() uint64 {
+ 	_g_ := getg()
+ 	return _g_.goid
+ }
+ 
  var ticks ticksType
  
  type ticksType struct {
EOF

CMD="-tN -r- `go env GOROOT`/src/runtime/runtime.go"
OS=`uname -s`

if ! patch --dry-run -R $CMD <<< "$PATCH" >> /dev/null; then
	if [[ $OS == "Darwin" ]]; then
		patch $CMD <<< "$PATCH" && echo "Runtime Patched!"
	else
		$SUDO patch $CMD <<< "$PATCH" && echo "Runtime Patched!"
	fi
fi
