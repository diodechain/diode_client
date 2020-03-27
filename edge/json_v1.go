// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package edge

import (
	"strconv"

	"github.com/buger/jsonparser"
	"github.com/diodechain/diode_go_client/util"
)

var (
	NullData = []byte("null")

	curlyBracketStart  = []byte("{")
	curlyBracketEnd    = []byte("}")
	squareBracketStart = []byte("[")
	squareBracketEnd   = []byte("]")
	doubleQuote        = []byte(`"`)
	comma              = []byte(",")
)

type JSON_V1 struct{}

func jsonString(rawData []byte, location string) string {
	value, _, _, _ := jsonparser.Get(rawData, location)
	if value == nil {
		return ""
	}
	return string(value)
}

func jsonInteger(rawData []byte, location string) int64 {
	value, _, _, _ := jsonparser.Get(rawData, location)
	if value == nil {
		return -1
	}
	if util.IsHexNumber(value) {
		return int64(util.DecodeStringToIntForce(string(value)))
	}
	num, err := strconv.Atoi(string(value))
	if err != nil {
		return -2
	}
	return int64(num)
}

// for merkle tree, TODO: refactor this
// func BitstringToUint(src string) {}

func isJSONObj(json []byte) bool {
	if len(json) == 0 {
		return false
	}
	return (json[0] == curlyBracketStart[0]) && (json[len(json)-1] == curlyBracketEnd[0])
}

func isJSONArr(json []byte) bool {
	if len(json) == 0 {
		return false
	}
	return (json[0] == squareBracketStart[0]) && (json[len(json)-1] == squareBracketEnd[0])
}

func isJSONStr(json []byte) bool {
	if len(json) == 0 {
		return false
	}
	return (json[0] == doubleQuote[0]) && (json[len(json)-1] == doubleQuote[0])
}

// JSONArrLen returns array length of json
// TODO: JSONObjLen
func JSONArrLen(json []byte) int {
	var length int
	var sqbCount int
	if !isJSONArr(json) {
		return length
	}
	src := json[1 : len(json)-1]
	for _, byt := range src {
		if byt == squareBracketStart[0] {
			sqbCount++
		} else if byt == squareBracketEnd[0] {
			sqbCount--
		} else if (byt == comma[0]) && (sqbCount == 0) {
			length++
		}
	}
	length++
	return length
}
