// Diode Network Client
// Copyright 2021 Diode
// Licensed under the Diode License, Version 1.1
package cmd

import (
	"github.com/gdamore/tcell/v2"
	"github.com/gdamore/tcell/v2/views"
)

type window struct {
	main   *views.CellView
	keybar *views.SimpleStyledText
	model  *model
	views.Panel
}

func (a *window) HandleEvent(ev tcell.Event) bool {

	switch ev := ev.(type) {
	case *tcell.EventKey:
		switch ev.Key() {
		case tcell.KeyCtrlC, tcell.KeyEnter, tcell.KeyEscape:
			app.Stop()
			return true
		case tcell.KeyRune:
			switch ev.Rune() {
			case 'Q', 'q':
				app.Stop()
				return true
			}
		}
	}
	return a.Panel.HandleEvent(ev)
}

func (a *window) Draw() {
	a.Panel.Draw()
}

func (a *window) updateKeys() {
	w := "[Q][CTRL+C][ESC][ENTER] Quit"
	a.keybar.SetMarkup(w)
}
