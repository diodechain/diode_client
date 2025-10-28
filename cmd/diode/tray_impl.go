//go:build !no_tray
// +build !no_tray

package main

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"strings"
	"sync"

	"github.com/diodechain/diode_client/config"
	"github.com/getlantern/systray"
)

// maybeRunWithTray starts the app within a system tray if the -tray flag is present.
// Returns true if the tray took over process execution.
func maybeRunWithTray(args []string) bool {
	if !hasTrayFlag(args) {
		return false
	}
	systray.Run(onTrayReady, onTrayExit)
	return true
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

// Add a sync.Once to guard app.Close()
var appCloseOnce sync.Once

// onTrayReady initializes the tray icon and starts the CLI in a goroutine
func onTrayReady() {
	// Set a simple generated icon and tooltip/title
	systray.SetIcon(genTrayIcon())
	systray.SetTitle("Diode Client")
	systray.SetTooltip("Diode Client is running")

	// Quit menu
	mQuit := systray.AddMenuItem("Quit", "Quit the app")

	// Start the CLI work in the background
	go func() {
		// Execute the CLI; flags (including -tray) will be parsed here as usual
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
		appCloseOnce.Do(func() {
			if !app.Closed() {
				app.Close()
			}
		})
		systray.Quit()
	}()
}

// onTrayExit is called when the tray is shutting down
func onTrayExit() {
	appCloseOnce.Do(func() {
		if !app.Closed() {
			app.Close()
		}
	})
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
	var buf bytes.Buffer
	_ = png.Encode(&buf, img)
	return buf.Bytes()
}
