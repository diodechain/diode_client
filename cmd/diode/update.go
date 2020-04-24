package main

import (
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"

	"github.com/kierdavis/ansi"

	"github.com/diodechain/go-update"
	"github.com/diodechain/go-update/progress"
	"github.com/diodechain/go-update/stores/github"
)

func doUpdate() {
	m := &update.Manager{
		Command: "diode",
		Store: &github.Store{
			Owner:   "diodechain",
			Repo:    "diode_go_client",
			Version: version,
		},
	}

	if runtime.GOOS == "windows" {
		m.Command += ".exe"
	}

	tarball, ok := download(m)
	if !ok {
		return
	}

	// searching for binary in path
	bin, err := exec.LookPath(m.Command)
	if err != nil {
		// just update local file
		bin = os.Args[0]
	}

	dir := filepath.Dir(bin)
	if err := m.InstallTo(tarball, dir); err != nil {
		printError("Error installing", err, 129)
	}

	cmd := path.Join(dir, m.Command)
	fmt.Printf("Updated, restarting %s...\n", cmd)

	err = update.Restart(cmd)
	if err != nil {
		printError(fmt.Sprintf("Error restarting %s", cmd), err, 129)
	}
}

func download(m *update.Manager) (string, bool) {
	ansi.HideCursor()
	defer ansi.ShowCursor()

	printInfo("Checking for updates...")

	// fetch the new releases
	releases, err := m.LatestReleases()
	if err != nil {
		printInfo(fmt.Sprintf("Error fetching releases: %s", err))
		return "", false
	}

	// no updates
	if len(releases) == 0 {
		printInfo("No updates")
		return "", false
	}

	// latest release
	latest := releases[0]
	printInfo(fmt.Sprintf("Found version %s > %s\n", latest.Version, version))

	a := latest.FindZip(runtime.GOOS, runtime.GOARCH)
	if a == nil {
		printInfo(fmt.Sprintf("No binary for your system (%s_%s)", runtime.GOOS, runtime.GOARCH))
		return "", false
	}

	// whitespace
	fmt.Println()

	// download tarball to a tmp dir
	tarball, err := a.DownloadProxy(progress.Reader)
	if err != nil {
		printError("Error downloading", err, 129)
	}

	return tarball, true
}
