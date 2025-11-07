//go:build !no_tray
// +build !no_tray

package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"os"
	"runtime"
	"strings"
	"sync"

	"github.com/diodechain/diode_client/config"
	"github.com/diodechain/diode_client/resources"
	"github.com/getlantern/systray"
)

// maybeRunWithTray starts the app within a system tray if the -tray flag is present.
// Returns true if the tray took over process execution.
func maybeRunWithTray(args []string) bool {
	if !hasTrayFlag(args) {
		return false
	}
	sanitizeTrayEnv()
	if err := systray.Run(onTrayReady, onTrayExit); err != nil {
		cfg := config.AppConfig
		msg := "Install libayatana-appindicator3 (and libgtk-3) to enable tray support."
		lower := strings.ToLower(err.Error())
		needsHint := strings.Contains(lower, "dlopen") || strings.Contains(lower, "dlsym") || strings.Contains(lower, "indicator") || strings.Contains(lower, "undefined symbol")
		if cfg != nil && cfg.Logger != nil {
			cfg.PrintError("Tray initialization failed", err)
			if needsHint {
				cfg.PrintInfo(msg)
			}
		} else {
			fmt.Fprintf(os.Stderr, "Tray initialization failed: %v\n", err)
			if needsHint {
				fmt.Fprintln(os.Stderr, msg)
			}
		}
		return false
	}
	return true
}

func sanitizeTrayEnv() {
	sanitizeEnvOnce.Do(func() {
		env := os.Environ()
		for _, kv := range env {
			key, value, ok := strings.Cut(kv, "=")
			if !ok {
				continue
			}
			switch key {
			case "PATH":
				if strings.Contains(value, "/snap/") {
					filtered := filterSnapPaths(value)
					if filtered != value {
						if filtered == "" {
							_ = os.Unsetenv(key)
						} else {
							_ = os.Setenv(key, filtered)
						}
					}
				}
			case "LD_LIBRARY_PATH", "LIBGL_DRIVERS_PATH", "LIBGL_DIR", "GTK_PATH", "GTK_EXE_PREFIX", "GDK_PIXBUF_MODULEDIR", "GDK_PIXBUF_MODULE_FILE", "GTK_IM_MODULE_FILE", "GIO_MODULE_DIR", "LOCPATH":
				if strings.Contains(value, "/snap/") {
					_ = os.Unsetenv(key)
				}
			default:
				if key == "SNAP" || strings.HasPrefix(key, "SNAP_") {
					_ = os.Unsetenv(key)
				}
			}
		}
	})
}

func filterSnapPaths(pathValue string) string {
	parts := strings.Split(pathValue, ":")
	filtered := make([]string, 0, len(parts))
	for _, p := range parts {
		if p == "" || strings.Contains(p, "/snap/") {
			continue
		}
		filtered = append(filtered, p)
	}
	return strings.Join(filtered, ":")
}

// hasTrayFlag checks whether the -tray flag is present and truthy
func hasTrayFlag(args []string) bool {
	for _, a := range args {
		if a == "-tray" || a == "--tray" {
			return true
		}
		if strings.HasPrefix(a, "-tray=") || strings.HasPrefix(a, "--tray=") {
			_, v, found := strings.Cut(a, "=")
			if found {
				v = strings.ToLower(v)
				if v == "1" || v == "t" || v == "true" || v == "yes" || v == "y" {
					return true
				}
			}
		}
	}
	return false
}

// Add sync.Once guards for shutdown and env sanitization
var (
	appCloseOnce    sync.Once
	sanitizeEnvOnce sync.Once
)

// onTrayReady initializes the tray icon and starts the CLI in a goroutine
func onTrayReady() {
	// Set a simple generated icon and tooltip/title
	systray.SetIcon(loadTrayIcon())
	systray.SetTitle("Diode Client")
	systray.SetTooltip("Diode Client is running")

	// Quit menu
	mQuit := systray.AddMenuItem("Quit", "Quit the app")

	// Start the CLI work in the background
	go func() {
		// Sanitize os.Args to strip the -tray flag so subcommands don't see it
		sanitizeTrayFlagFromArgs()
		// Execute the CLI after sanitizing flags
		err := diodeCmd.Execute()
		cfg := config.AppConfig
		if err != nil {
			if cfg != nil {
				cfg.PrintError("Couldn't execute command", err)
			}
		}
		// For one-off commands, exit the tray when done
		systray.Quit()
	}()

	// Handle Quit
	go func() {
		<-mQuit.ClickedCh
		appCloseOnce.Do(func() { safeAppClose() })
		systray.Quit()
	}()
}

// onTrayExit is called when the tray is shutting down
func onTrayExit() {
	appCloseOnce.Do(func() { safeAppClose() })
}

// loadTrayIcon returns icon bytes for the tray.
// - On Windows, use embedded .ico as-is.
// - On other platforms, convert embedded .ico to PNG.
// - If anything fails, fall back to a generated icon.
func loadTrayIcon() []byte {
	if len(resources.TrayICO) > 0 {
		// systray accepts .ico/.jpg/.png on macOS/Linux and .ico on Windows
		return resources.TrayICO
	}
	// Fallback to generated icon if embed missing
	return genTrayIcon()
}

// genTrayIcon produces a small 16x16 PNG for the tray icon at runtime
func genTrayIcon() []byte {
	const size = 16
	img := image.NewRGBA(image.Rect(0, 0, size, size))
	// Fill background
	bg := color.RGBA{R: 0, G: 170, B: 200, A: 255}
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			img.Set(x, y, bg)
		}
	}
	// Draw a lighter bar to hint a 'D'
	bar := color.RGBA{R: 230, G: 245, B: 255, A: 255}
	for y := 3; y < size-3; y++ {
		img.Set(4, y, bar)
		img.Set(5, y, bar)
	}
	for x := 5; x < size-4; x++ {
		img.Set(x, 3, bar)
		img.Set(x, size-4, bar)
	}
	// On Windows, systray expects .ico bytes, not PNG.
	if runtime.GOOS == "windows" {
		if b, err := encodeICO(img); err == nil {
			return b
		}
		// Fallback to PNG if ICO encoding somehow failed
	}
	var buf bytes.Buffer
	_ = png.Encode(&buf, img)
	return buf.Bytes()
}

// encodeICO encodes a single 32-bit (with alpha) 16x16 icon as a minimal .ico.
// For Windows tray, the systray library requires .ico formatted bytes.
func encodeICO(img *image.RGBA) ([]byte, error) {
	w := img.Bounds().Dx()
	h := img.Bounds().Dy()
	if w <= 0 || h <= 0 || w > 255 || h > 255 {
		// This implementation supports 1-byte width/height values (1..255).
		return nil, nil
	}

	// Compute sizes for the DIB section
	pixelDataSize := w * h * 4 // 32bpp BGRA pixels
	// AND mask: 1 bit per pixel, padded to 32-bit boundary per row
	andRowBytes := ((w + 31) / 32) * 4
	andMaskSize := andRowBytes * h
	bytesInRes := 40 + pixelDataSize + andMaskSize // 40 = BITMAPINFOHEADER size

	// Build ICO header (ICONDIR + ICONDIRENTRY)
	var out bytes.Buffer
	// ICONDIR
	_ = binary.Write(&out, binary.LittleEndian, uint16(0)) // reserved
	_ = binary.Write(&out, binary.LittleEndian, uint16(1)) // type = icon
	_ = binary.Write(&out, binary.LittleEndian, uint16(1)) // count
	// ICONDIRENTRY
	out.WriteByte(byte(w))                                  // width
	out.WriteByte(byte(h))                                  // height
	out.WriteByte(0)                                        // color count
	out.WriteByte(0)                                        // reserved
	_ = binary.Write(&out, binary.LittleEndian, uint16(1))  // planes
	_ = binary.Write(&out, binary.LittleEndian, uint16(32)) // bit count
	_ = binary.Write(&out, binary.LittleEndian, uint32(bytesInRes))
	_ = binary.Write(&out, binary.LittleEndian, uint32(6+16)) // image offset after headers

	// DIB (BITMAPINFOHEADER + pixel data + AND mask)
	// BITMAPINFOHEADER
	_ = binary.Write(&out, binary.LittleEndian, uint32(40))            // biSize
	_ = binary.Write(&out, binary.LittleEndian, int32(w))              // biWidth
	_ = binary.Write(&out, binary.LittleEndian, int32(h*2))            // biHeight (XOR + AND)
	_ = binary.Write(&out, binary.LittleEndian, uint16(1))             // biPlanes
	_ = binary.Write(&out, binary.LittleEndian, uint16(32))            // biBitCount
	_ = binary.Write(&out, binary.LittleEndian, uint32(0))             // biCompression = BI_RGB
	_ = binary.Write(&out, binary.LittleEndian, uint32(pixelDataSize)) // biSizeImage
	_ = binary.Write(&out, binary.LittleEndian, int32(0))              // biXPelsPerMeter
	_ = binary.Write(&out, binary.LittleEndian, int32(0))              // biYPelsPerMeter
	_ = binary.Write(&out, binary.LittleEndian, uint32(0))             // biClrUsed
	_ = binary.Write(&out, binary.LittleEndian, uint32(0))             // biClrImportant

	// Pixel data: bottom-up rows, BGRA bytes
	for y := h - 1; y >= 0; y-- {
		off := img.PixOffset(0, y)
		for x := 0; x < w; x++ {
			r := img.Pix[off+0]
			g := img.Pix[off+1]
			b := img.Pix[off+2]
			a := img.Pix[off+3]
			out.WriteByte(b)
			out.WriteByte(g)
			out.WriteByte(r)
			out.WriteByte(a)
			off += 4
		}
	}

	// AND mask: zeros (transparent handled via alpha in 32-bit pixel data)
	if andMaskSize > 0 {
		out.Write(make([]byte, andMaskSize))
	}

	return out.Bytes(), nil
}

// sanitizeTrayFlagFromArgs removes any -tray/--tray flag (with or without value)
// from os.Args so subcommand-specific flag parsers don't reject it when placed
// after the command name (e.g., `diode time -tray=true`).
func sanitizeTrayFlagFromArgs() {
	if len(os.Args) < 2 {
		return
	}
	filtered := make([]string, 0, len(os.Args))
	filtered = append(filtered, os.Args[0])
	for _, a := range os.Args[1:] {
		if a == "-tray" || a == "--tray" || strings.HasPrefix(a, "-tray=") || strings.HasPrefix(a, "--tray=") {
			continue
		}
		filtered = append(filtered, a)
	}
	os.Args = filtered
}

// safeAppClose avoids panicking if the app hasn't been initialized (closeCh nil)
func safeAppClose() {
	if app.closeCh != nil {
		if !app.Closed() {
			app.Close()
		}
	}
}
