package db

import (
	"bytes"
	"fmt"
	"os"
	"sync"
)

var (
	DB     *Database
	DBPath string
	// maybe it won't work on windows
	sepNewline = []byte("\n")
	sepEqual   = []byte("=")
)

type Database struct {
	db     *os.File
	path   string
	keys   [][]byte
	values [][]byte
	stat   os.FileInfo
	// maybe write data async in the future
	// dirty bool
	rm    sync.Mutex
	empty bool
}

func OpenFile(path string) (*Database, error) {
	rfile, err := os.OpenFile(path, os.O_CREATE|os.O_RDONLY, 0644)
	if err != nil {
		return nil, err
	}
	stat, err := rfile.Stat()
	if err != nil {
		return nil, err
	}
	size := stat.Size()
	data := make([]byte, size)
	_, err = rfile.Read(data)
	if err != nil {
		return nil, err
	}
	// close rfile
	rfile.Close()
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}
	keys := [][]byte{}
	values := [][]byte{}
	keyValues := bytes.Split(data, sepNewline)
	for _, v := range keyValues {
		pair := bytes.Split(v, sepEqual)
		if len(pair) == 2 {
			keys = append(keys, pair[0])
			values = append(values, pair[1])
		}
	}

	db := &Database{
		db:     file,
		path:   path,
		stat:   stat,
		keys:   keys,
		values: values,
		empty:  size <= 0,
	}
	return db, nil
}

func (db *Database) findKey(key []byte) int {
	index := -1
	for i, v := range db.keys {
		if bytes.Equal(v, key) {
			index = i
			break
		}
	}
	return index
}

func (db *Database) serialize(start int) ([]byte, error) {
	if start < 0 {
		return nil, fmt.Errorf(("Cannot start from negative position"))
	}
	keysLen := len(db.keys)
	valuesLen := len(db.values)
	if keysLen != valuesLen {
		return nil, fmt.Errorf(("Data corrupted"))
	}
	if keysLen == 0 {
		return nil, fmt.Errorf(("Empty key value"))
	}
	data := [][]byte{}
	pairs := make([][]byte, 2)
	for i := start; i < keysLen; i++ {
		pairs[0] = db.keys[i]
		pairs[1] = db.values[i]
		data = append(data, bytes.Join(pairs, sepEqual))
	}
	res := bytes.Join(data, sepNewline)
	if start > 0 {
		res = append(sepNewline, res...)
	}
	return res, nil
}

func (db *Database) offset(key []byte) (int, int) {
	keysLen := len(db.keys)
	valuesLen := len(db.values)
	index := -1
	offset := 0
	if keysLen == 0 || valuesLen == 0 {
		return index, offset
	}
	data := [][]byte{}
	res := []byte{}
	pairs := make([][]byte, 2)
	for i, v := range db.keys {
		if bytes.Equal(v, key) {
			index = i
			break
		} else {
			pairs[0] = v
			pairs[1] = db.values[i]
			data = append(data, bytes.Join(pairs, sepEqual))
		}
	}
	res = bytes.Join(data, sepNewline)
	if index != 0 {
		offset = len(res)
	}
	return index, offset
}

func (db *Database) Get(key []byte) ([]byte, error) {
	db.rm.Lock()
	defer db.rm.Unlock()
	index := db.findKey(key)
	if index < 0 {
		return nil, fmt.Errorf("key not found")
	}
	return db.values[index], nil
}

// Put data to file database
// Notice: remember not to use = and \n in value or key
func (db *Database) Put(key []byte, value []byte) (err error) {
	db.rm.Lock()
	defer db.rm.Unlock()
	serializedData := []byte{}
	index, offset := db.offset(key)
	if index < 0 {
		// append to key
		db.keys = append(db.keys, key)
		db.values = append(db.values, value)
		// write new line
		if !db.empty {
			key = append(sepNewline, key...)
		}
		serializedData = bytes.Join([][]byte{
			key,
			value,
		}, sepEqual)
	} else {
		db.values[index] = value
		// update existed value
		serializedData, err = db.serialize(index)
	}
	// serializedData, err := db.serialize()
	// if err != nil {
	// 	return err
	// }
	// write data to file
	_, err = db.db.WriteAt(serializedData, int64(offset))
	db.empty = false
	return err
}

func (db *Database) Close() error {
	db.rm.Lock()
	defer db.rm.Unlock()
	err := db.db.Close()
	return err
}
