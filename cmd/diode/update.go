package main

import (
	"fmt"
	"io"
	"os"
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

func writeLastUpdateAt() {
	lastUpdateAt := time.Now()
	lastUpdateAtByt := util.DecodeInt64ToBytes(lastUpdateAt.Unix())
	db.DB.Put("last_update_at", lastUpdateAtByt)
}

func updateHandler() (err error) {
	_, err = doUpdate(updateRestartStandalone)
	return err
}

type updateRestartMode int

const (
	updateRestartStandalone updateRestartMode = iota
	updateRestartDeferred
)

func runDaemonUpdateWithConfig(args []string, cfg *config.Config) (string, error) {
	if len(args) == 0 || args[0] != "update" {
		return "", newExitStatusError(2, "missing update command")
	}
	return doUpdateWithConfig(cfg, updateRestartDeferred)
}

func doUpdate(restartMode updateRestartMode) (string, error) {
	return doUpdateWithConfig(config.AppConfig, restartMode)
}

func doUpdateWithConfig(cfg *config.Config, restartMode updateRestartMode) (string, error) {
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

	tarball, ok, err := download(cfg, m)
	if !ok {
		// Will recheck for an update in 24 hours
		go func() {
			time.Sleep(time.Hour * 24)
			_, _ = doUpdate(updateRestartStandalone)
		}()
		if err == nil {
			writeLastUpdateAt()
		}
		if err != nil {
			return "", newExitStatusError(1, "%s", err.Error())
		}
		return "", nil
	}

	dir := updateInstallDir()
	if err := m.InstallTo(tarball, dir); err != nil {
		cfg.PrintError("Error installing", err)
		return "", newExitStatusError(129, "%s", err.Error())
	}

	cmd := filepath.Join(dir, m.Command)
	fmt.Fprintf(updateOutputWriter(cfg), "Updated, restarting %s...\n", cmd)
	writeLastUpdateAt()
	if restartMode == updateRestartDeferred {
		return cmd, nil
	}
	update.Restart(cmd)
	return "", nil
}

func updateInstallDir() string {
	bin, err := os.Executable()
	if err != nil || bin == "" {
		bin = os.Args[0]
	}
	return updateInstallDirFromExecutable(bin, filepath.EvalSymlinks)
}

func updateInstallDirFromExecutable(bin string, evalSymlinks func(string) (string, error)) string {
	if abs, err := filepath.Abs(bin); err == nil {
		bin = abs
	}
	if resolved, err := evalSymlinks(bin); err == nil {
		bin = resolved
	}
	return filepath.Dir(bin)
}

func download(cfg *config.Config, m *update.Manager) (string, bool, error) {
	ansi.HideCursor()
	defer ansi.ShowCursor()

	cfg.PrintInfo("Checking for updates...")

	// fetch the new releases
	releases, err := m.LatestReleases()
	if err != nil {
		cfg.PrintInfo(fmt.Sprintf("Error fetching releases: %s", err))
		return "", false, err
	}

	// no updates
	if len(releases) == 0 {
		cfg.PrintInfo("No updates")
		return "", false, nil
	}

	// latest release
	latest := releases[0]
	cfg.PrintInfo(fmt.Sprintf("Found version %s > %s\n", latest.Version, version))

	a := latest.FindZip(runtime.GOOS, runtime.GOARCH)
	if a == nil {
		cfg.PrintInfo(fmt.Sprintf("No binary for your system (%s_%s)", runtime.GOOS, runtime.GOARCH))
		return "", false, nil
	}

	// whitespace
	fmt.Fprintln(updateOutputWriter(cfg))

	// download tarball to a tmp dir
	tarball, err := a.DownloadProxy(progress.Reader)
	if err != nil {
		cfg.PrintError("Error downloading", err)
	}

	return tarball, true, nil
}

func updateOutputWriter(cfg *config.Config) io.Writer {
	if cfg != nil && cfg.StdoutWriter != nil {
		return cfg.StdoutWriter
	}
	return os.Stdout
}
