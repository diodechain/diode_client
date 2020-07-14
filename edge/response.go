// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package edge

import (
	"reflect"
)

// Response struct
// Item represents key/value of response
type Item struct {
	Key   string
	Value []byte
}

type responseID struct {
	RequestID uint64
}

type errorResponse struct {
	RequestID uint64
	Payload   []string
}

type blockPeakResponse struct {
	RequestID uint64
	Payload   struct {
		Type        string
		BlockNumber uint64
	}
}

type blockResponse struct {
	RequestID uint64
	Payload   struct {
		Type string
		// can decode by self
		// Block []interface{}
		Block struct {
			Coinbase struct {
				Key   string
				Value []byte // should be null
			}
			Header struct {
				Key   string
				Value []interface{}
			}
			Receipts struct {
				Key   string
				Value []interface{}
			}
			Transactions struct {
				Key   string
				Value []interface{}
			}
		}
	}
}

type blockHeaderResponse struct {
	RequestID uint64
	Payload   struct {
		Type        string
		Items       [8]Item
		MinerPubkey []byte
	}
}

type blockquickResponse struct {
	RequestID uint64
	Payload   struct {
		Type  string
		Items []uint64
	}
}

// type helloResponse struct {}

type ticketThanksResponse struct {
	RequestID uint64
	Payload   struct {
		Type      string
		Result    string
		PaidBytes []byte
	}
}

type ticketTooOldResponse struct {
	RequestID uint64
	Payload   struct {
		Type   string
		Result string
		Min    []byte
	}
}

type ticketTooLowResponse struct {
	RequestID uint64
	Payload   struct {
		Type             string
		Result           string
		BlockHash        []byte
		TotalConnections uint64
		TotalBytes       uint64
		LocalAddr        []byte
		DeviceSig        []byte
	}
}

type accountResponse struct {
	RequestID uint64
	Payload   struct {
		Type        string
		Items       [4]Item
		MerkleProof []interface{}
	}
}

type accountRootsResponse struct {
	RequestID uint64
	Payload   struct {
		Type         string
		AccountRoots [][]byte
	}
}

type accountValueResponse struct {
	RequestID uint64
	Payload   struct {
		Type        string
		MerkleProof []interface{}
	}
}

type portOpenResponse struct {
	RequestID uint64
	Payload   struct {
		Method string
		Result string
		Ref    string
	}
}

type objectResponse struct {
	RequestID uint64
	Payload   struct {
		Type   string
		Ticket struct {
			Location         string // should be "location"
			ServerID         []byte
			PeakBlock        uint64
			FleetAddr        []byte
			TotalConnections uint64
			TotalBytes       uint64
			LocalAddr        []byte
			DeviceSig        []byte
			ServerSig        []byte
		}
	}
}

type serverObjectResponse struct {
	RequestID uint64
	Payload   struct {
		Type         string
		ServerObject []interface{}
	}
}

type stateRootsResponse struct {
	RequestID uint64
	Payload   struct {
		Type       string
		StateRoots [][]byte
	}
}

type transactionResponse struct {
	RequestID uint64
	Payload   struct {
		Type   string
		Result string
	}
}

// type portSendResponse struct {}
// type portCloseResponse struct {}

func findItemInItems(items interface{}, key string) (item Item, err error) {
	val := reflect.ValueOf(items)
	switch val.Kind() {
	case reflect.Slice:
	case reflect.Array:
		var ok bool
		i := 0
		len := val.Len()
		for ; i < len; i++ {
			v := val.Index(i)
			if item, ok = v.Interface().(Item); ok {
				if item.Key == key {
					return
				}
			}
		}
	default:
		err = errWrongTypeForItems
		return
	}
	err = errKeyNotFoundInItems
	return
}
