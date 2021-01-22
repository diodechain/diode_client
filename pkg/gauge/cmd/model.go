// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package cmd

import (
	"fmt"
	"github.com/gdamore/tcell/v2"
)

type model struct {
	x    int
	y    int
	endx int
	endy int
	hide bool
	enab bool
	loc  string
	rows []string
}

// SetRow set the row content
func (m *model) SetRow(r int, s string) {
	if r >= m.endy {
		return
	}
	if len(s) <= 0 {
		return
	}
	m.rows[r] = s
}

func (m *model) GetBounds() (int, int) {
	return m.endx, m.endy
}

func (m *model) MoveCursor(offx, offy int) {
	m.x += offx
	m.y += offy
	m.limitCursor()
}

func (m *model) limitCursor() {
	if m.x < 0 {
		m.x = 0
	}
	if m.x > m.endx-1 {
		m.x = m.endx - 1
	}
	if m.y < 0 {
		m.y = 0
	}
	if m.y > m.endy-1 {
		m.y = m.endy - 1
	}
	m.loc = fmt.Sprintf("Cursor is %d,%d", m.x, m.y)
}

func (m *model) GetCursor() (int, int, bool, bool) {
	return m.x, m.y, m.enab, !m.hide
}

func (m *model) SetCursor(x int, y int) {
	m.x = x
	m.y = y

	m.limitCursor()
}

func (m *model) GetCell(x, y int) (rune, tcell.Style, []rune, int) {
	var ch rune
	style := tcell.StyleDefault
	if x >= m.endx || y >= m.endy {
		return ch, style, nil, 1
	}
	if len(m.rows[y]) > x {
		ch = rune(m.rows[y][x])
	}
	return ch, style, nil, 1
}
