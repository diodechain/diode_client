package main

import (
	"fmt"
	"log"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/kierdavis/ansi"

	"github.com/tj/go-update"
	"github.com/tj/go-update/progress"
	"github.com/tj/go-update/stores/github"
)

func doUpdate() {
	ansi.HideCursor()
	defer ansi.ShowCursor()

	m := &update.Manager{
		Command: "diode",
		Store: &github.Store{
			Owner:   "diodechain",
			Repo:    "diode_go_client",
			Version: version,
		},
	}

	// fetch the new releases
	releases, err := m.LatestReleases()
	if err != nil {
		log.Fatalf("error fetching releases: %s", err)
	}

	// no updates
	if len(releases) == 0 {
		log.Print("no updates")
		return
	}

	// latest release
	latest := releases[0]

	// find the tarball for this system
	log.Printf("Looking for %s %s in %+v\n", runtime.GOOS, runtime.GOARCH, latest)

	var a *update.Asset
	for _, b := range latest.Assets {
		ext := filepath.Ext(b.Name)
		log.Printf("Found: %s\n", b.Name)
		if strings.Contains(b.Name, runtime.GOOS) && ext == ".zip" {
			a = b
			break
		}
	}

	// a := latest.FindTarball(runtime.GOOS, runtime.GOARCH)
	if a == nil {
		log.Print("no binary for your system")
		return
	}

	// whitespace
	fmt.Println()

	// download tarball to a tmp dir
	tarball, err := a.DownloadProxy(progress.Reader)
	if err != nil {
		log.Fatalf("error downloading: %s", err)
	}

	// install it
	if err := m.Install(tarball); err != nil {
		log.Fatalf("error installing: %s", err)
	}

	fmt.Printf("Updated to %s\n", latest.Version)
}
