// +build linux,legacy_appindicator
//go:build linux && legacy_appindicator

package systray

/*
#cgo linux CFLAGS: -DUSE_LEGACY_APPINDICATOR

#include "systray.h"
*/
import "C"
