// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package db

import (
	// "os"
	"bytes"
	"os"
	"testing"
)

type DBTest struct {
	Key   string
	Value []byte
}

var (
	// should remove testdb after test
	dbFilePath = "./test.db"
	dbTests    = []DBTest{
		{
			Key:   "hello",
			Value: []byte("world"),
		},
		{
			Key:   "diode",
			Value: []byte("blockchain"),
		},
		{
			Key:   "decentralized",
			Value: []byte("PKI"),
		},
		{
			Key:   "ibtc",
			Value: []byte("iot"),
		},
	}
)

func TestPutAndGetInDB(t *testing.T) {
	db, err := OpenFile(dbFilePath)
	if err != nil {
		panic(err)
	}
	for _, v := range dbTests {
		db.Put(v.Key, v.Value)
	}
	for _, v := range dbTests {
		gv, err := db.Get(v.Key)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(v.Value, gv) {
			t.Errorf("Cannot get value from file db")
		}
	}
	// Update values
	addOn := "ethereum"
	for i, v := range dbTests {
		v.Value = append(v.Value, addOn...)
		dbTests[i] = v
		db.Put(v.Key, v.Value)
	}
	for _, v := range dbTests {
		gv, err := db.Get(v.Key)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(v.Value, gv) {
			t.Errorf("Cannot get value from file db")
		}
	}
	db.Close()
	// delete file
	err = os.Remove(dbFilePath)
	if err != nil {
		panic(err)
	}
}
