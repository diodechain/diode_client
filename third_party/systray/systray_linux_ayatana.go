// +build linux,!legacy_appindicator
//go:build linux && !legacy_appindicator

package systray

/*
#include "systray.h"
*/
import "C"
