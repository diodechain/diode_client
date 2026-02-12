#!/bin/bash
SUDO=`which sudo`
read -r -d '' PATCH <<'EOF'
diff --git src/runtime/runtime.go src/runtime/runtime.go
index 33ecc260dd..dea79f6095 100644
--- src/runtime/runtime.go
+++ src/runtime/runtime.go
@@ -13,6 +13,12 @@ import (
 //go:generate go run mkduff.go
 //go:generate go run mkfastlog2table.go
 
+// GetGoID returns the goid
+func GetGoID() int64 {
+	_g_ := getg()
+	return _g_.goid
+}
+
 var ticks struct {
 	lock mutex
 	pad  uint32 // ensure 8-byte alignment of val on 386
EOF

CMD="-tN -r- `go env GOROOT`/src/runtime/runtime.go"
OS=`uname -s`

if ! patch --dry-run -R $CMD <<< "$PATCH" >> /dev/null; then
	$SUDO patch  $CMD <<< "$PATCH" && echo "Runtime Patched!"
	if [[ $OS == "Darwin" ]]; then
		patch $CMD <<< "$PATCH" && echo "Runtime Patched!"
	else
		$SUDO patch $CMD <<< "$PATCH" && echo "Runtime Patched!"
	fi
fi
