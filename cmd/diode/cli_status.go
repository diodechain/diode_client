package main

import "fmt"

type exitStatusError struct {
	code int
	msg  string
}

func (e *exitStatusError) Error() string {
	return e.msg
}

func (e *exitStatusError) Status() int {
	return e.code
}

func newExitStatusError(code int, format string, args ...interface{}) error {
	return &exitStatusError{
		code: code,
		msg:  fmt.Sprintf(format, args...),
	}
}
