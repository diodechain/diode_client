// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package edge

// TODO: make sure it works
// Request struct
type blockPeakRequest struct {
	RequestID uint64
	Payload   struct {
		Method string
	}
}

type blockRequest struct {
	RequestID uint64
	Payload   struct {
		Method      string
		BlockNumber uint64
	}
}

type blockHeaderRequest struct {
	RequestID uint64
	Payload   struct {
		Method      string
		BlockNumber uint64
	}
}

type blockquickRequest struct {
	RequestID uint64
	Payload   struct {
		Method     string
		LastValid  uint64
		WindowSize uint64
	}
}

type helloRequest struct {
	RequestID uint64
	Payload   struct {
		Method string
		Flag   uint64
	}
}

type ticketRequest struct {
	RequestID uint64
	Payload   struct {
		Method           string
		BlockNumber      uint64
		FleetAddr        []byte
		TotalConnections uint64
		TotalBytes       uint64
		LocalAddr        []byte
		DeviceSig        []byte
	}
}

type accountRequest struct {
	RequestID uint64
	Payload   struct {
		Method      string
		BlockNumber uint64
		Address     []byte
	}
}

type accountRootsRequest struct {
	RequestID uint64
	Payload   struct {
		Method      string
		BlockNumber uint64
		Address     []byte
	}
}

type accountValueRequest struct {
	RequestID uint64
	Payload   struct {
		Method      string
		BlockNumber uint64
		Address     []byte
		Key         []byte
	}
}

type portOpenRequest struct {
	RequestID uint64
	Payload   struct {
		Method   string
		DeviceID []byte
		Port     uint64
		Mode     string
	}
}

type portSendRequest struct {
	RequestID uint64
	Payload   struct {
		Method string
		Ref    uint64
		Data   []byte
	}
}

type portCloseRequest struct {
	RequestID uint64
	Payload   struct {
		Method string
		Ref    uint64
	}
}

type objectRequest struct {
	RequestID uint64
	Payload   struct {
		Method   string
		DeviceID []byte
	}
}

type serverObjectRequest struct {
	RequestID uint64
	Payload   struct {
		Method   string
		ServerID []byte
	}
}

type stateRootsRequest struct {
	RequestID uint64
	Payload   struct {
		Method      string
		BlockNumber uint64
	}
}
