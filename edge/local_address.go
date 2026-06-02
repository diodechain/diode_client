// Diode Network Client
// Copyright 2021 Diode
// Licensed under the Diode License, Version 1.1
package edge

import (
	"math/big"

	"github.com/ethereum/go-ethereum/rlp"
)

const (
	// MaxTicketTimestampLag is how far behind the chain peak a metadata timestamp may be.
	MaxTicketTimestampLag = 16 * 3600

	localAddrMetadataPrefix        = 2
	localAddrLegacyPreferredPrefix = 0
	localAddrLegacySecondaryPrefix = 1
)

// LocalAddrFormat describes how local_address bytes are encoded.
type LocalAddrFormat int

const (
	LocalAddrFormatEmpty LocalAddrFormat = iota
	LocalAddrFormatLegacyPreferred
	LocalAddrFormatLegacySecondary
	LocalAddrFormatMetadata
	LocalAddrFormatUnknown
)

// LocalAddrInfo is the decoded relay hint and optional creation timestamp.
type LocalAddrInfo struct {
	Format       LocalAddrFormat
	Preferred    []Address
	Timestamp    uint64
	HasTimestamp bool
}

// ParseLocalAddr decodes all supported local_address encodings.
func ParseLocalAddr(local []byte, serverID Address) LocalAddrInfo {
	var addrLen = len(Address{})
	if len(local) == 0 {
		return LocalAddrInfo{
			Format:    LocalAddrFormatEmpty,
			Preferred: []Address{serverID},
		}
	}

	if len(local) >= 2 && local[0] == localAddrMetadataPrefix {
		info := parseMetadataLocalAddr(local[1:])
		info.Format = LocalAddrFormatMetadata
		if len(info.Preferred) == 0 {
			info.Preferred = []Address{serverID}
		}
		return info
	}

	var addr Address
	if len(local) == addrLen+1 && local[0] == localAddrLegacyPreferredPrefix {
		copy(addr[:], local[1:1+addrLen])
		return LocalAddrInfo{
			Format:    LocalAddrFormatLegacyPreferred,
			Preferred: []Address{addr, serverID},
		}
	}
	if len(local) == addrLen+1 && local[0] == localAddrLegacySecondaryPrefix {
		copy(addr[:], local[1:1+addrLen])
		return LocalAddrInfo{
			Format:    LocalAddrFormatLegacySecondary,
			Preferred: []Address{serverID, addr},
		}
	}

	return LocalAddrInfo{
		Format:    LocalAddrFormatUnknown,
		Preferred: []Address{serverID},
	}
}

func parseMetadataLocalAddr(meta []byte) LocalAddrInfo {
	var info LocalAddrInfo
	var pairs []interface{}
	if err := rlp.DecodeBytes(meta, &pairs); err != nil {
		return info
	}
	for _, p := range pairs {
		pair, ok := p.([]interface{})
		if !ok || len(pair) != 2 {
			continue
		}
		key, ok := pair[0].([]byte)
		if !ok {
			continue
		}
		switch string(key) {
		case "s":
			info.Preferred = decodePreferredAddresses(pair[1])
		case "t":
			info.Timestamp = rlpUintFromBytes(bytesAsSlice(pair[1]))
			info.HasTimestamp = true
		}
	}
	return info
}

func bytesAsSlice(raw interface{}) []byte {
	switch v := raw.(type) {
	case []byte:
		return v
	default:
		return nil
	}
}

func rlpUintFromBytes(b []byte) uint64 {
	if len(b) == 0 {
		return 0
	}
	return new(big.Int).SetBytes(b).Uint64()
}

func decodePreferredAddresses(raw interface{}) []Address {
	list, ok := raw.([]interface{})
	if !ok {
		return nil
	}
	var out []Address
	for _, item := range list {
		b, ok := item.([]byte)
		if !ok || len(b) != len(Address{}) {
			continue
		}
		var addr Address
		copy(addr[:], b)
		out = append(out, addr)
	}
	return out
}

// LocalAddrInfo returns parsed local_address data for this ticket.
func (ct *DeviceTicket) LocalAddrInfo() LocalAddrInfo {
	return ParseLocalAddr(ct.LocalAddr, ct.ServerID)
}

// IsRecentAtPeak reports whether the ticket is fresh relative to the validated chain peak.
// When metadata includes timestamp "t", that value is used instead of block number / bytes-only heuristics.
func (ct *DeviceTicket) IsRecentAtPeak(peakBlock, peakTimestamp uint64) bool {
	info := ct.LocalAddrInfo()
	if info.HasTimestamp {
		return isRecentByMetadataTimestamp(ct.Version, ct.Epoch, info.Timestamp, peakTimestamp)
	}
	if ct.Version == 2 {
		peakEpoch := TicketEpochFromTimestamp(peakTimestamp)
		return ct.Epoch >= peakEpoch
	}
	if peakBlock < ct.BlockNumber {
		return true
	}
	// ~16 hours at 15s block time
	return (peakBlock - ct.BlockNumber) < (16*3600)/15
}

func isRecentByMetadataTimestamp(version, ticketEpoch, ticketTS, peakTS uint64) bool {
	peakEpoch := TicketEpochFromTimestamp(peakTS)
	if version == 2 {
		if ticketEpoch < peakEpoch {
			return false
		}
		if ticketEpoch > peakEpoch {
			return true
		}
	} else if version == 1 {
		ticketEpoch = TicketEpochFromTimestamp(ticketTS)
		if ticketEpoch < peakEpoch {
			return false
		}
		if ticketEpoch > peakEpoch {
			return true
		}
	}
	if peakTS <= ticketTS {
		return true
	}
	return peakTS-ticketTS < MaxTicketTimestampLag
}

// AgeMetric returns a sortable age hint (aligned with diode_client_ex TicketV2.block_number/1).
func (ct *DeviceTicket) AgeMetric() *big.Int {
	const (
		epochMul = 0xFFFFFFFFFFFFFFFF
		vsnMul   = 0xFFFFFFFFFFFFFFF
	)
	info := ct.LocalAddrInfo()
	m := new(big.Int)
	if info.HasTimestamp {
		if ct.Version == 2 {
			m.SetUint64(ct.Epoch)
			m.Mul(m, new(big.Int).SetUint64(epochMul))
			vsn := new(big.Int).SetUint64(vsnMul)
			vsn.Lsh(vsn, 1)
			m.Add(m, vsn)
			m.Add(m, new(big.Int).SetUint64(info.Timestamp))
			return m
		}
		m.SetUint64(2)
		m.Mul(m, new(big.Int).SetUint64(epochMul))
		m.Add(m, new(big.Int).SetUint64(info.Timestamp))
		return m
	}
	if ct.Version == 2 {
		m.SetUint64(ct.Epoch)
		m.Mul(m, new(big.Int).SetUint64(epochMul))
		m.Add(m, ct.TotalBytes)
		return m
	}
	return new(big.Int).SetUint64(ct.BlockNumber)
}
