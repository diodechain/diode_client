package control

import (
	"encoding/pem"
	"strconv"
	"strings"

	"github.com/diodechain/diode_client/config"
	diodeCrypto "github.com/diodechain/diode_client/crypto"
	"github.com/diodechain/diode_client/rpc"
	"github.com/diodechain/diode_client/util"
)

const maskedConfigValue = "<********************************>"

func applyPrivate(ctx *ApplyContext, op Operation) error {
	if ctx.DB == nil {
		return nil
	}
	if op.Delete {
		return ctx.DB.Del("private")
	}
	value, err := StringFromValue(op.Value)
	if err != nil {
		return err
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return ctx.DB.Del("private")
	}
	pemBytes, err := normalizePrivateKey(value)
	if err != nil {
		return err
	}
	return ctx.DB.Put("private", pemBytes)
}

func exportPrivate(ctx *ApplyContext, unsafe bool) ([]ConfigListEntry, error) {
	if ctx.DB == nil {
		return nil, nil
	}
	value, err := ctx.DB.Get("private")
	if err != nil || len(value) == 0 {
		return nil, nil
	}
	entries := []ConfigListEntry{}
	if ctx.Config != nil {
		entries = append(entries, ConfigListEntry{Key: "<address>", Value: ctx.Config.ClientAddr.HexString()})
	}
	privateValue := maskedConfigValue
	if unsafe {
		block, _ := pem.Decode(value)
		if block == nil {
			return nil, strconv.ErrSyntax
		}
		privKey, err := diodeCrypto.DerToECDSA(block.Bytes)
		if err != nil {
			return nil, err
		}
		privateValue = util.EncodeToString(privKey.D.Bytes())
	}
	entries = append(entries, ConfigListEntry{Key: "private", Value: privateValue})
	return entries, nil
}

func applyFleet(ctx *ApplyContext, op Operation) error {
	if op.Delete {
		if ctx.Surface == SurfaceConfig && ctx.DB != nil {
			if err := ctx.DB.Del("fleet"); err != nil {
				return err
			}
		}
		ctx.Config.FleetAddr = config.DefaultFleetAddr
		return nil
	}
	value, err := StringFromValue(op.Value)
	if err != nil {
		return err
	}
	addr, err := util.DecodeAddress(value)
	if err != nil {
		return err
	}
	ctx.Config.FleetAddr = addr
	if ctx.Surface == SurfaceConfig && ctx.DB != nil {
		return ctx.DB.Put("fleet", addr[:])
	}
	return nil
}

func exportFleet(ctx *ApplyContext, unsafe bool) ([]ConfigListEntry, error) {
	if ctx.DB == nil {
		return nil, nil
	}
	value, err := ctx.DB.Get("fleet")
	if err != nil || len(value) == 0 {
		return nil, nil
	}
	var addr util.Address
	copy(addr[:], value)
	return []ConfigListEntry{{Key: "fleet", Value: addr.HexString()}}, nil
}

func applyLastUpdateAt(ctx *ApplyContext, op Operation) error {
	if ctx.DB == nil {
		return nil
	}
	if op.Delete {
		return ctx.DB.Del("last_update_at")
	}
	value, err := IntFromValue(op.Value)
	if err != nil {
		return err
	}
	return ctx.DB.Put("last_update_at", util.DecodeInt64ToBytes(int64(value)))
}

func exportLastUpdateAt(ctx *ApplyContext, unsafe bool) ([]ConfigListEntry, error) {
	if ctx.DB == nil {
		return nil, nil
	}
	value, err := ctx.DB.Get("last_update_at")
	if err != nil || len(value) == 0 {
		return nil, nil
	}
	return []ConfigListEntry{{Key: "last_update_at", Value: strconv.Itoa(util.DecodeBytesToInt(value))}}, nil
}

func ExportOpaqueDBEntries(ctx *ApplyContext, managed map[string]bool) []ConfigListEntry {
	if ctx == nil || ctx.DB == nil {
		return nil
	}
	keys := ctx.DB.List()
	out := make([]ConfigListEntry, 0, len(keys))
	for _, key := range keys {
		if managed[key] {
			continue
		}
		value, err := ctx.DB.Get(key)
		if err != nil {
			continue
		}
		out = append(out, ConfigListEntry{Key: key, Value: util.EncodeToString(value)})
	}
	return out
}

func normalizePrivateKey(raw string) ([]byte, error) {
	if rpc.ValidatePrivatePEM([]byte(raw)) {
		return []byte(raw), nil
	}
	trimmed := strings.TrimPrefix(raw, "0x")
	trimmed = strings.TrimPrefix(trimmed, "0X")
	if !util.IsHex([]byte(trimmed)) {
		return nil, strconv.ErrSyntax
	}
	decoded, err := util.DecodeString(trimmed)
	if err != nil {
		return nil, err
	}
	der, err := rpc.LoadPrivateKey(decoded)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), nil
}
