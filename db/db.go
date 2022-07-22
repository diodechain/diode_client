// Diode Network Client
// Copyright 2021 Diode
// Licensed under the Diode License, Version 1.1
package db

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"path"
	"sync"

	"github.com/diodechain/diode_client/util"
)

const (
	databaseVersionMagic uint64 = 4389235283
)

var (
	DB                 *Database
	DBPath             string
	ErrSizeDidNotMatch = fmt.Errorf("incorrect size of written bytes")
	ErrKeyNotFound     = fmt.Errorf("key not found")
)

type Database struct {
	path   string
	values map[string][]byte
	// maybe write data async in the future
	// dirty bool
	rm          sync.Mutex
	buffer      []byte
	backup      *Database
	backup_keys map[string]bool
}

func OpenFile(filepath string, withbackup bool) (*Database, error) {
	os.MkdirAll(path.Dir(filepath), 0700)

	// Migration code from version 0.3.1
	if filepath == util.DefaultDBPath() {
		oldDefault := path.Join(".", "db", "private.db")
		if _, err := os.Stat(filepath); err != nil {
			if _, err := os.Stat(oldDefault); err == nil {
				log.Printf("Migrating database from %s to %s\n", oldDefault, filepath)
				err = os.Rename(oldDefault, filepath)
				if err != nil {
					return nil, err
				}
			}
		}
	}

	f, err := os.OpenFile(filepath, os.O_CREATE|os.O_RDONLY, 0600)
	if err != nil {
		return nil, err
	}
	defer func(f *os.File) {
		f.Close()
	}(f)
	r := bufio.NewReader(f)
	magic, _ := binary.ReadUvarint(r)
	values := make(map[string][]byte)
	if magic == databaseVersionMagic {
		numTuples, err := binary.ReadUvarint(r)
		if err != nil {
			return nil, err
		}
		for i := numTuples; i > 0; i-- {
			size64, _ := binary.ReadUvarint(r)
			key := make([]byte, size64)
			size, err := r.Read(key)
			if size != len(key) || err != nil {
				return nil, err
			}
			size64, _ = binary.ReadUvarint(r)
			value := make([]byte, size64)
			size, err = r.Read(value)
			if size != len(value) || err != nil {
				return nil, err
			}
			values[string(key)] = value
		}
	}
	db := &Database{
		path:        filepath,
		values:      values,
		buffer:      make([]byte, 1024),
		backup:      nil,
		backup_keys: make(map[string]bool),
	}

	if withbackup {
		backup, err := OpenFile(filepath+".bck", false)
		if err == nil {
			db.backup = backup
		}
	}

	return db, nil
}

// Get reads data from the file database
func (db *Database) Get(key string) ([]byte, error) {
	db.rm.Lock()
	defer db.rm.Unlock()
	ret := db.values[key]
	if ret == nil {
		return nil, ErrKeyNotFound
	}
	return ret, nil
}

// Put data to file database
func (db *Database) Put(key string, value []byte) (err error) {
	db.rm.Lock()
	db.values[key] = value
	err = db.store()
	db.rm.Unlock()

	if err == nil && db.backup_keys[key] == true {
		db.doBackup(key)
	}
	return err
}

// Del deletes data from the file database
func (db *Database) Del(key string) (err error) {
	db.rm.Lock()
	defer db.rm.Unlock()
	delete(db.values, key)
	return db.store()
}

// List returns all keys
func (db *Database) List() []string {
	db.rm.Lock()
	defer db.rm.Unlock()

	list := []string{}
	for key := range db.values {
		list = append(list, key)
	}
	return list
}

func (db *Database) store() error {
	f, err := os.OpenFile(db.path+".tmp", os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	w := bufio.NewWriter(f)
	err = db.put(w, databaseVersionMagic)
	if err != nil {
		return err
	}
	err = db.put(w, uint64(len(db.values)))
	if err != nil {
		return err
	}
	for key, value := range db.values {
		db.put(w, uint64(len(key)))
		r, err := w.Write([]byte(key))
		if len(key) != r || err != nil {
			return err
		}
		db.put(w, uint64(len(value)))
		r, err = w.Write(value)
		if len(value) != r || err != nil {
			return err
		}
	}
	err = w.Flush()
	if err != nil {
		return err
	}
	err = f.Close()
	if err != nil {
		return err
	}
	// This renaming makes the operation atomic
	// the database will be written 100% correct or not at
	return os.Rename(db.path+".tmp", db.path)
}

func (db *Database) put(w *bufio.Writer, num uint64) error {
	size := binary.PutUvarint(db.buffer, num)
	r, err := w.Write(db.buffer[:size])
	if err != nil {
		return err
	}
	if size != r {
		return ErrSizeDidNotMatch
	}
	return nil
}

func (db *Database) Close() error {
	return nil
}

func (db *Database) EnableBackup(key string) {
	if db.backup == nil {
		return
	}
	db.backup_keys[key] = true
	db.doBackup(key)
}

func (origin *Database) doBackup(key string) {
	if origin.backup == nil {
		return
	}
	backup := origin.backup
	originValue, _ := origin.Get(key)
	backupValue, _ := backup.Get(key)
	if originValue != nil {
		// Creating backup store if not existing or different from original value
		if backupValue == nil || bytes.Compare(originValue, backupValue) != 0 {
			backup.Put(key, originValue)
		}
	} else if backupValue != nil {
		// Restoring from backup store
		origin.Put(key, backupValue)
	}
}
