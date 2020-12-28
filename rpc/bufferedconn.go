package rpc

import (
	"bufio"
	"net"
	"time"
)

type bufferedConn struct {
	conn    net.Conn
	buffer  *bufio.Writer
	flusher chan bool
}

func NewBufferedConn(conn net.Conn) *bufferedConn {
	buffConn := &bufferedConn{
		conn:    conn,
		buffer:  bufio.NewWriter(conn),
		flusher: make(chan bool, 128),
	}

	go func() {
		for {
			x := <-buffConn.flusher
			if x {
				return
			}
			buffConn.buffer.Flush()
		}
	}()

	return buffConn
}

// Read reads data from the connection.
// Read can be made to time out and return an error after a fixed
// time limit; see SetDeadline and SetReadDeadline.
func (buffConn *bufferedConn) Read(b []byte) (n int, err error) {
	return buffConn.conn.Read(b)
}

// Write writes data to the connection.
// Write can be made to time out and return an error after a fixed
// time limit; see SetDeadline and SetWriteDeadline.
func (buffConn *bufferedConn) Write(b []byte) (n int, err error) {
	n, err = buffConn.buffer.Write(b)
	buffConn.flusher <- false
	return
}

// Close closes the connection.
// Any blocked Read or Write operations will be unblocked and return errors.
func (buffConn *bufferedConn) Close() error {
	err := buffConn.conn.Close()
	buffConn.flusher <- true
	return err
}

// LocalAddr returns the local network address.
func (buffConn *bufferedConn) LocalAddr() net.Addr {
	return buffConn.conn.LocalAddr()
}

// RemoteAddr returns the remote network address.
func (buffConn *bufferedConn) RemoteAddr() net.Addr {
	return buffConn.conn.RemoteAddr()
}

// SetDeadline sets the read and write deadlines associated
// with the connection. It is equivalent to calling both
// SetReadDeadline and SetWriteDeadline.
//
// A deadline is an absolute time after which I/O operations
// fail instead of blocking. The deadline applies to all future
// and pending I/O, not just the immediately following call to
// Read or Write. After a deadline has been exceeded, the
// connection can be refreshed by setting a deadline in the future.
//
// If the deadline is exceeded a call to Read or Write or to other
// I/O methods will return an error that wraps os.ErrDeadlineExceeded.
// This can be tested using errors.Is(err, os.ErrDeadlineExceeded).
// The error's Timeout method will return true, but note that there
// are other possible errors for which the Timeout method will
// return true even if the deadline has not been exceeded.
//
// An idle timeout can be implemented by repeatedly extending
// the deadline after successful Read or Write calls.
//
// A zero value for t means I/O operations will not time out.
func (buffConn *bufferedConn) SetDeadline(t time.Time) error {
	return buffConn.conn.SetDeadline(t)
}

// SetReadDeadline sets the deadline for future Read calls
// and any currently-blocked Read call.
// A zero value for t means Read will not time out.
func (buffConn *bufferedConn) SetReadDeadline(t time.Time) error {
	return buffConn.conn.SetReadDeadline(t)
}

// SetWriteDeadline sets the deadline for future Write calls
// and any currently-blocked Write call.
// Even if write times out, it may return n > 0, indicating that
// some of the data was successfully written.
// A zero value for t means Write will not time out.
func (buffConn *bufferedConn) SetWriteDeadline(t time.Time) error {
	return buffConn.conn.SetWriteDeadline(t)
}
