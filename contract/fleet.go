// Diode Network Client
// Copyright 2019 IoT Blockchain Technology Corporation LLC (IBTC)
// Licensed under the Diode License, Version 1.0
package contract

import (
	"strings"

	"github.com/diodechain/diode_go_client/accounts/abi"
	"github.com/diodechain/diode_go_client/crypto/sha3"
	"github.com/diodechain/diode_go_client/util"
)

/**
 * The storage position of fleet contract
 */
const (
	DiodeRegistryIndex = iota
	OperatorIndex
	AccountantIndex
	ValueIndex
	AccessRootIndex
	DeviceRootIndex
	DeviceWhitelistIndex
	AccessWhitelistIndex

	// FleetContractABI is the input ABI used to generate the binding from.
	FleetContractABI = "[{\"constant\":false,\"inputs\":[{\"name\":\"_client\",\"type\":\"address\"},{\"name\":\"_value\",\"type\":\"bool\"}],\"name\":\"SetDeviceWhitelist\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"\",\"type\":\"address\"},{\"name\":\"\",\"type\":\"address\"}],\"name\":\"accessWhitelist\",\"outputs\":[{\"name\":\"\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"accountant\",\"outputs\":[{\"name\":\"\",\"type\":\"address\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"_device\",\"type\":\"address\"},{\"name\":\"_client\",\"type\":\"address\"},{\"name\":\"_value\",\"type\":\"bool\"}],\"name\":\"SetAccessWhitelist\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"operator\",\"outputs\":[{\"name\":\"\",\"type\":\"address\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"\",\"type\":\"address\"}],\"name\":\"deviceWhitelist\",\"outputs\":[{\"name\":\"\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"name\":\"_diodeRegistry\",\"type\":\"address\"},{\"name\":\"_operator\",\"type\":\"address\"},{\"name\":\"_accountant\",\"type\":\"address\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"constructor\"}]"
	// FleetContractBin is the compiled bytecode used for deploying new contracts.
	FleetContractBin = "0x608060405234801561001057600080fd5b5060405160608061030183398101604090815281516020830151919092015160018054600160a060020a03938416600160a060020a03199182161790915560008054948416948216949094179093556002805492909116919092161790556102848061007d6000396000f3006080604052600436106100775763ffffffff7c01000000000000000000000000000000000000000000000000000000006000350416633c5f7d46811461007c5780634ef1aee4146100a45780634fb3ccc5146100df578063504f04b714610110578063570ca7351461013c578063d90bd65114610151575b600080fd5b34801561008857600080fd5b506100a2600160a060020a03600435166024351515610172565b005b3480156100b057600080fd5b506100cb600160a060020a03600435811690602435166101b4565b604080519115158252519081900360200190f35b3480156100eb57600080fd5b506100f46101d4565b60408051600160a060020a039092168252519081900360200190f35b34801561011c57600080fd5b506100a2600160a060020a036004358116906024351660443515156101e3565b34801561014857600080fd5b506100f4610234565b34801561015d57600080fd5b506100cb600160a060020a0360043516610243565b600154600160a060020a0316331461018957600080fd5b600160a060020a03919091166000908152600660205260409020805460ff1916911515919091179055565b600760209081526000928352604080842090915290825290205460ff1681565b600254600160a060020a031681565b600154600160a060020a031633146101fa57600080fd5b600160a060020a03928316600090815260076020908152604080832094909516825292909252919020805460ff1916911515919091179055565b600154600160a060020a031681565b60066020526000908152604090205460ff16815600a165627a7a723058205bc6b976a1f573c8d758f7014f6797ea418c25bcfe315a780a9164cfc10d7ad80029"
)

// FleetContract is fleet contract struct
type FleetContract struct {
	ABI abi.ABI
}

// Address represents an Ethereum address
type Address = util.Address

// NewFleetContract returns fleet contract struct
func NewFleetContract() (fleetContract FleetContract, err error) {
	var fleetABI abi.ABI
	fleetABI, err = abi.JSON(strings.NewReader(FleetContractABI))
	if err != nil {
		return
	}
	fleetContract.ABI = fleetABI
	return
}

// DeployFleetContract returns deploy fleet contract data
func (fleetContract *FleetContract) DeployFleetContract(_diodeRegistry Address, _operator Address, _accountant Address) (data []byte, err error) {
	var decBin []byte
	var packData []byte
	decBin, err = util.DecodeString(FleetContractBin)
	if err != nil {
		return
	}
	packData, err = fleetContract.ABI.Pack("", _diodeRegistry, _operator, _accountant)
	if err != nil {
		return
	}
	data = append(decBin, packData...)
	return
}

// SetDeviceWhitelist returns set device whilist function call data
func (fleetContract *FleetContract) SetDeviceWhitelist(_client Address, _whilisted bool) (data []byte, err error) {
	data, err = fleetContract.ABI.Pack("SetDeviceWhitelist", _client, _whilisted)
	if err != nil {
		return
	}
	return
}

// DeviceWhitelistKey returns storage key of device whitelist of givin address
func DeviceWhitelistKey(addr Address) []byte {
	index := util.IntToBytes(DeviceWhitelistIndex)
	padIndex := util.PaddingBytesPrefix(index, 0, 32)
	padAddr := util.PaddingBytesPrefix(addr[:], 0, 32)
	hash := sha3.NewKeccak256()
	hash.Write(append(padAddr, padIndex...))
	return hash.Sum(nil)
}

// AccessWhitelistKey returns storage key of access whitelist of givin address
func AccessWhitelistKey(deviceAddr Address, clientAddr Address) []byte {
	index := util.IntToBytes(AccessWhitelistIndex)
	padIndex := util.PaddingBytesPrefix(index, 0, 32)
	padDeviceAddr := util.PaddingBytesPrefix(deviceAddr[:], 0, 32)
	padClientAddr := util.PaddingBytesPrefix(clientAddr[:], 0, 32)
	hash := sha3.NewKeccak256()
	hash.Write(append(padDeviceAddr, padIndex...))
	baseKey := hash.Sum(nil)
	hash = sha3.NewKeccak256()
	hash.Write(append(padClientAddr, baseKey...))
	return hash.Sum(nil)
}
