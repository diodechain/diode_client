// Diode Network Client
// Copyright 2021 Diode
// Licensed under the Diode License, Version 1.1
package edge

import (
	"math/big"
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
		TotalConnections *big.Int
		TotalBytes       *big.Int
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

type moonAccountValueResponse struct {
	RequestID uint64
	Payload   struct {
		Type  string
		Value []byte
	}
}

type portSendResponse struct {
	RequestID uint64
	Payload   struct {
		Type   string
		Result string
	}
}

type portOpenResponse struct {
	RequestID uint64
	Payload   struct {
		Type   string
		Result string
		Ref    string
	}
}

type portOpen2Response struct {
	RequestID uint64
	Payload   struct {
		Type         string
		PhysicalPort uint64
	}
}

type portOpen2ResponseWithResult struct {
	RequestID uint64
	Payload   struct {
		Type         string
		PhysicalPort uint64
		Result       string
	}
}

type portOpen2ResponseWithMethod struct {
	RequestID uint64
	Payload   struct {
		Type         string
		Method       string
		PhysicalPort uint64
		Result       string
	}
}

type emptyResponse struct {
	RequestID uint64
	Payload   struct {
		Type  string // "response"
		Empty string // ""
	}
}

type objectResponse struct {
	RequestID uint64
	Payload   struct {
		Type   string
		Ticket struct {
			ObjectType       string // "ticket"
			ServerID         []byte
			PeakBlock        uint64
			FleetAddr        []byte
			TotalConnections *big.Int
			TotalBytes       *big.Int
			LocalAddr        []byte
			DeviceSig        []byte
			ServerSig        []byte
		}
	}
}

type objectResponseV2 struct {
	RequestID uint64
	Payload   struct {
		Type   string
		Ticket struct {
			ObjectType       string // "ticketv2"
			ServerID         []byte
			ChainID          uint64
			Epoch            uint64
			FleetAddr        []byte
			TotalConnections *big.Int
			TotalBytes       *big.Int
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

func (response *objectResponse) makeDeviceTicket() *DeviceTicket {
	serverID := [20]byte{}
	copy(serverID[:], response.Payload.Ticket.ServerID)
	fleetAddr := [20]byte{}
	copy(fleetAddr[:], response.Payload.Ticket.FleetAddr)
	return &DeviceTicket{
		Version:          1,
		ServerID:         serverID,
		BlockNumber:      response.Payload.Ticket.PeakBlock,
		BlockHash:        nil,
		FleetAddr:        fleetAddr,
		TotalConnections: response.Payload.Ticket.TotalConnections,
		TotalBytes:       response.Payload.Ticket.TotalBytes,
		DeviceSig:        response.Payload.Ticket.DeviceSig,
		ServerSig:        response.Payload.Ticket.ServerSig,
		LocalAddr:        response.Payload.Ticket.LocalAddr,
	}
}

func (response *objectResponseV2) makeDeviceTicket() *DeviceTicket {
	serverID := [20]byte{}
	copy(serverID[:], response.Payload.Ticket.ServerID)
	fleetAddr := [20]byte{}
	copy(fleetAddr[:], response.Payload.Ticket.FleetAddr)
	return &DeviceTicket{
		Version:          2,
		ServerID:         serverID,
		ChainID:          response.Payload.Ticket.ChainID,
		Epoch:            response.Payload.Ticket.Epoch,
		FleetAddr:        fleetAddr,
		TotalConnections: response.Payload.Ticket.TotalConnections,
		TotalBytes:       response.Payload.Ticket.TotalBytes,
		DeviceSig:        response.Payload.Ticket.DeviceSig,
		ServerSig:        response.Payload.Ticket.ServerSig,
		LocalAddr:        response.Payload.Ticket.LocalAddr,
	}
}
