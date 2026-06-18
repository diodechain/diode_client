#!/bin/bash
go build && ./diode_go_client --fleet 0x565c1d0dd84dd8b7bc01973c930d658d86cd74ff --dbpath "./db/two.db" -runsocks=true -runproxy=false $*
