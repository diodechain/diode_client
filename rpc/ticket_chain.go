// Diode Network Client
// Copyright 2026 Diode
// Licensed under the Diode License, Version 1.1
package rpc

import (
	"fmt"
	"time"

	"github.com/diodechain/diode_client/config"
	"github.com/diodechain/diode_client/edge"
)

const moonbeamHeadCacheTTL = 15 * time.Second

// GetMoonBlockPeak returns the latest Moonbeam block number reported by the relay.
func (client *Client) GetMoonBlockPeak() (uint64, error) {
	rawPeak, err := client.CallContext("glmr:getblockpeak")
	if err != nil {
		return 0, fmt.Errorf("failed to fetch Moonbeam block peak: %w", err)
	}
	peak, ok := rawPeak.(uint64)
	if !ok {
		return 0, fmt.Errorf("moonbeam block peak has unexpected type %T", rawPeak)
	}
	return peak, nil
}

// GetMoonBlockHeader returns a Moonbeam block reference from the relay.
func (client *Client) GetMoonBlockHeader(blockNumber uint64) (edge.BlockReference, error) {
	rawHeader, err := client.CallContext("glmr:getblockheader", blockNumber)
	if err != nil {
		return edge.BlockReference{}, fmt.Errorf("failed to fetch Moonbeam block %d: %w", blockNumber, err)
	}
	header, ok := rawHeader.(edge.BlockReference)
	if !ok {
		return edge.BlockReference{}, fmt.Errorf("moonbeam block header has unexpected type %T", rawHeader)
	}
	return header, nil
}

func (client *Client) ticketChainHead(chainID uint64) (edge.BlockReference, error) {
	switch chainID {
	case config.DiodeChainID:
		return client.diodeTicketChainHead()
	case config.MoonbeamChainID:
		return client.moonbeamTicketChainHead()
	default:
		return edge.BlockReference{}, fmt.Errorf("unsupported ticket chain id: %d", chainID)
	}
}

// GetTicketChainHead returns the current block reference for the configured ticket chain.
func (client *Client) GetTicketChainHead() (edge.BlockReference, error) {
	return client.ticketChainHead(client.config.TicketChainID())
}

func applyTicketChainReference(
	ticket *edge.DeviceTicket,
	chainID uint64,
	head edge.BlockReference,
	preferred []edge.Address,
) error {
	if head.Number == 0 {
		return fmt.Errorf("no valid block header for ticket")
	}
	localAddr, err := edge.CreateTicketLocalAddress(preferred, head.Timestamp)
	if err != nil {
		return err
	}
	ticket.LocalAddr = localAddr

	switch chainID {
	case config.DiodeChainID:
		ticket.Version = 1
		ticket.BlockNumber = head.Number
		ticket.BlockHash = head.Hash
	case config.MoonbeamChainID:
		epoch := edge.TicketEpochFromTimestamp(head.Timestamp)
		if epoch == 0 {
			epoch = 1
		}
		ticket.Version = 2
		ticket.ChainID = chainID
		ticket.Epoch = epoch
	default:
		return fmt.Errorf("unsupported ticket chain id: %d", chainID)
	}
	return nil
}

func (client *Client) diodeTicketChainHead() (edge.BlockReference, error) {
	blockNumber, blockHash := client.LastValid()
	header := client.GetBlockHeaderValid(blockNumber)
	if header.Number() == 0 || header.Number() != blockNumber {
		return edge.BlockReference{}, fmt.Errorf("no valid diode block header for ticket")
	}
	hash := make([]byte, len(blockHash))
	copy(hash, blockHash[:])
	return edge.BlockReference{
		Number:    header.Number(),
		Timestamp: header.Timestamp(),
		Hash:      hash,
	}, nil
}

func (client *Client) moonbeamTicketChainHead() (edge.BlockReference, error) {
	client.ticketHeadMu.Lock()
	defer client.ticketHeadMu.Unlock()

	if !client.moonbeamHeadAt.IsZero() && time.Since(client.moonbeamHeadAt) < moonbeamHeadCacheTTL {
		return cloneBlockReference(client.moonbeamHead), nil
	}

	blockNumber, err := client.GetMoonBlockPeak()
	if err != nil {
		return edge.BlockReference{}, err
	}
	if blockNumber == 0 {
		return edge.BlockReference{}, fmt.Errorf("moonbeam block peak is zero")
	}

	header, err := client.GetMoonBlockHeader(blockNumber)
	if err != nil {
		return edge.BlockReference{}, err
	}
	if header.Number != blockNumber {
		return edge.BlockReference{}, fmt.Errorf(
			"moonbeam block header number mismatch: requested %d, got %d",
			blockNumber,
			header.Number,
		)
	}
	client.moonbeamHead = cloneBlockReference(header)
	client.moonbeamHeadAt = time.Now()
	return cloneBlockReference(header), nil
}

func cloneBlockReference(reference edge.BlockReference) edge.BlockReference {
	reference.Hash = append([]byte(nil), reference.Hash...)
	return reference
}
