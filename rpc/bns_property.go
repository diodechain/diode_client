package rpc

import (
	"strings"

	"github.com/diodechain/diode_client/contract"
)

// BNSProperties reads the properties stored on a BNS name.
// The Diode L1 entry is used when that name resolves there. Otherwise the Moonbeam entry is used.
// A missing properties slot is an empty list.
func (client *Client) BNSProperties(name string) ([]string, error) {
	name = strings.ToLower(name)
	_, diodeErr := client.ResolveDiodeBNS(name)
	if diodeErr == nil {
		return contract.ReadPropertyStrings(name, emptyPropertiesSlot(func(slot []byte) ([]byte, error) {
			return client.GetAccountValueRaw(0, contract.BNSAddr, slot)
		}))
	}
	if diodeErr != errEmptyBNSresult {
		return nil, diodeErr
	}
	_, moonErr := client.ResolveMoonBNS(name)
	if moonErr == nil {
		return contract.ReadPropertyStrings(name, emptyPropertiesSlot(func(slot []byte) ([]byte, error) {
			raw, err := client.GetMoonAccountValueRaw(contract.MoonBNSAddr, slot)
			if err != nil || len(raw) == 0 {
				return nil, err
			}
			return raw, nil
		}))
	}
	if moonErr != errEmptyBNSresult {
		return nil, moonErr
	}
	return nil, errEmptyBNSresult
}

// emptyPropertiesSlot turns a missing properties-length slot into an empty array.
// Later missing words stay errors so a partial read does not fall through to the zone destinations.
func emptyPropertiesSlot(read func(slot []byte) ([]byte, error)) func(slot []byte) ([]byte, error) {
	length := true
	return func(slot []byte) ([]byte, error) {
		raw, err := read(slot)
		if length {
			length = false
			if err != nil && strings.Contains(err.Error(), "key not found") {
				return make([]byte, 32), nil
			}
		}
		return raw, err
	}
}

// ResolvePrefixDestination returns the destination address for labels under zone.
// found is false when no PX record matches and the caller should use the zone destinations.
func (client *Client) ResolvePrefixDestination(zone string, labels []string) (string, bool, error) {
	properties, err := client.BNSProperties(zone)
	if err != nil {
		return "", false, err
	}
	return contract.PrefixDestination(labels, properties)
}
