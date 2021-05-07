package main

import (
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"time"

	"github.com/diodechain/diode_client/command"
	"github.com/diodechain/diode_client/config"
	"github.com/diodechain/diode_client/db"
	"github.com/diodechain/diode_client/util"

	"github.com/kierdavis/ansi"

	"github.com/diodechain/go-update"
	"github.com/diodechain/go-update/progress"
	"github.com/diodechain/go-update/stores/github"
)

var (
	updateCmd = &command.Command{
		Name:        "update",
		HelpText:    `  Force updating the diode client version.`,
		ExampleText: `  diode update`,
		Run:         updateHandler,
		Type:        command.EmptyConnectionCommand,
	}
)

func updateHandler() (err error) {
	lastUpdateAt := time.Now()
	lastUpdateAtByt := util.DecodeInt64ToBytes(lastUpdateAt.Unix())
	db.DB.Put("last_update_at", lastUpdateAtByt)
	doUpdate()
	return
}

func doUpdate() int {
	cfg := config.AppConfig
	m := &update.Manager{
		Command: "diode",
		Store: &github.Store{
			Owner:   "diodechain",
			Repo:    "diode_client",
			Version: version,
		},
	}

	if runtime.GOOS == "windows" {
		m.Command += ".exe"
	}

	tarball, ok := download(m)
	if !ok {
		// Will recheck for an update in 24 hours
		go func() {
			time.Sleep(time.Hour * 24)
			doUpdate()
		}()
		return 0
	}

	// searching for binary in path
	bin, err := exec.LookPath(m.Command)
	if err != nil {
		// just update local file
		bin = os.Args[0]
	}

	// find the real path of execute file if the file was symlink
	binExe, err := filepath.EvalSymlinks(bin)
	if err != nil {
		binExe = bin
	}

	dir := filepath.Dir(binExe)
	if err := m.InstallTo(tarball, dir); err != nil {
		cfg.PrintError("Error installing", err)
		return 129
	}

	cmd := path.Join(dir, m.Command)
	fmt.Printf("Updated, restarting %s...\n", cmd)

	update.Restart(cmd)
	return 0
}

func download(m *update.Manager) (string, bool) {
	cfg := config.AppConfig
	ansi.HideCursor()
	defer ansi.ShowCursor()

	cfg.PrintInfo("Checking for updates...")

	// fetch the new releases
	releases, err := m.LatestReleases()
	if err != nil {
		cfg.PrintInfo(fmt.Sprintf("Error fetching releases: %s", err))
		return "", false
	}

	// no updates
	if len(releases) == 0 {
		cfg.PrintInfo("No updates")
		return "", false
	}

	// latest release
	latest := releases[0]
	cfg.PrintInfo(fmt.Sprintf("Found version %s > %s\n", latest.Version, version))

	a := latest.FindZip(runtime.GOOS, runtime.GOARCH)
	if a == nil {
		cfg.PrintInfo(fmt.Sprintf("No binary for your system (%s_%s)", runtime.GOOS, runtime.GOARCH))
		return "", false
	}

	// whitespace
	fmt.Println()

	// download tarball to a tmp dir
	tarball, err := a.DownloadProxy(progress.Reader)
	if err != nil {
		cfg.PrintError("Error downloading", err)
	}

	return tarball, true
}
