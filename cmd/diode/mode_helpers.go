package main

func beginRuntimeMode(name string) {
	if !isDaemonApplyRequest() {
		return
	}
	app.StopMode()
	app.BeginMode(name)
}

func registerRuntimeCleanup(cleanup func()) {
	if cleanup == nil {
		return
	}
	if isDaemonApplyRequest() {
		app.ModeDefer(cleanup)
		return
	}
	app.Defer(cleanup)
}
