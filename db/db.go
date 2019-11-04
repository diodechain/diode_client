package db

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"sync"
)

const (
	databaseVersionMagic uint64 = 4389235283
)

var (
	DB     *Database
	DBPath string
)

type Database struct {
	path   string
	values map[string][]byte
	// maybe write data async in the future
	// dirty bool
	rm     sync.Mutex
	buffer []byte
}

func OpenFile(path string) (*Database, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDONLY, 0644)
	if err != nil {
		return nil, err
	}
	r := bufio.NewReader(f)
	magic, _ := binary.ReadUvarint(r)
	values := make(map[string][]byte)
	if magic == databaseVersionMagic {
		numTuples, err := binary.ReadUvarint(r)
		if err != nil {
			log.Fatal(err)
		}
		for i := numTuples; i > 0; i-- {
			size64, err := binary.ReadUvarint(r)
			key := make([]byte, size64)
			size, err := r.Read(key)
			if size != len(key) || err != nil {
				log.Fatal(err)
			}
			size64, err = binary.ReadUvarint(r)
			value := make([]byte, size64)
			size, err = r.Read(value)
			if size != len(value) || err != nil {
				log.Fatal(err)
			}
			values[string(key)] = value
		}
	}
	db := &Database{
		path:   path,
		values: values,
		buffer: make([]byte, 1024),
	}
	return db, nil
}

func (db *Database) Get(key string) ([]byte, error) {
	db.rm.Lock()
	defer db.rm.Unlock()
	ret := db.values[key]
	if ret == nil {
		return nil, fmt.Errorf("key not found")
	}
	return ret, nil
}

// Put data to file database
// Notice: remember not to use = and \n in value or key
func (db *Database) Put(key string, value []byte) (err error) {
	db.rm.Lock()
	defer db.rm.Unlock()
	db.values[key] = value
	return db.store()
}

func (db *Database) store() error {
	f, err := os.OpenFile(db.path+".tmp", os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	w := bufio.NewWriter(f)
	db.put(w, databaseVersionMagic)
	db.put(w, uint64(len(db.values)))
	for key, value := range db.values {
		db.put(w, uint64(len(key)))
		r, err := w.Write([]byte(key))
		if len(key) != r || err != nil {
			log.Fatal(err)
		}
		db.put(w, uint64(len(value)))
		r, err = w.Write(value)
		if len(value) != r || err != nil {
			log.Fatal(err)
		}
	}
	err = w.Flush()
	if err != nil {
		log.Fatal(err)
	}
	err = f.Close()
	if err != nil {
		log.Fatal(err)
	}
	// This renaming makes the operation atomic
	// the database will be written 100% correct or not at
	return os.Rename(db.path+".tmp", db.path)
}

func (db *Database) put(w *bufio.Writer, num uint64) {
	size := binary.PutUvarint(db.buffer, num)
	r, err := w.Write(db.buffer[:size])
	if size != r || err != nil {
		log.Fatal(err)
	}
}

func (db *Database) Close() error {
	return nil
}
