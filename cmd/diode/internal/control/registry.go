package control

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/diodechain/diode_client/config"
)

func DefaultDescriptors() []Descriptor {
	return []Descriptor{
		{
			Key:      "public",
			Surfaces: surfaceSet(SurfaceCLI, SurfaceAPI, SurfaceJoin),
			Aliases:  aliasSet("public", SurfaceAPI, SurfaceJoin),
			Apply: func(ctx *ApplyContext, op Operation) error {
				items, err := stringListOp(op, ctx.Surface == SurfaceJoin, "public")
				if err != nil {
					return err
				}
				ctx.Config.PublicPublishedPorts = config.StringValues(items)
				return nil
			},
		},
		{
			Key:      "private",
			Surfaces: surfaceSet(SurfaceCLI, SurfaceAPI, SurfaceJoin, SurfaceConfig),
			Aliases:  aliasSet("private", SurfaceAPI, SurfaceJoin, SurfaceConfig),
			Apply: func(ctx *ApplyContext, op Operation) error {
				if ctx.Surface == SurfaceConfig {
					return applyPrivate(ctx, op)
				}
				items, err := stringListOp(op, ctx.Surface == SurfaceJoin, "private")
				if err != nil {
					return err
				}
				ctx.Config.PrivatePublishedPorts = config.StringValues(items)
				return nil
			},
			ExportConfig: exportPrivate,
		},
		{
			Key:      "protected",
			Surfaces: surfaceSet(SurfaceCLI, SurfaceAPI, SurfaceJoin),
			Aliases:  aliasSet("protected", SurfaceAPI, SurfaceJoin),
			Apply: func(ctx *ApplyContext, op Operation) error {
				items, err := stringListOp(op, ctx.Surface == SurfaceJoin, "protected")
				if err != nil {
					return err
				}
				ctx.Config.ProtectedPublishedPorts = config.StringValues(items)
				return nil
			},
		},
		{
			Key:      "sshd",
			Surfaces: surfaceSet(SurfaceCLI, SurfaceJoin),
			Aliases:  aliasSet("sshd", SurfaceJoin),
			Apply: func(ctx *ApplyContext, op Operation) error {
				items, err := stringListOp(op, ctx.Surface == SurfaceJoin, "sshd")
				if err != nil {
					return err
				}
				ctx.Config.SSHPublishedServices = config.StringValues(items)
				return nil
			},
		},
		{
			Key:      "bind",
			Surfaces: surfaceSet(SurfaceCLI, SurfaceAPI, SurfaceJoin),
			Aliases: map[Surface][]string{
				SurfaceCLI:  {"bind"},
				SurfaceAPI:  {"bind", "binds"},
				SurfaceJoin: {"bind"},
			},
			Apply: func(ctx *ApplyContext, op Operation) error {
				items, err := stringListOp(op, ctx.Surface == SurfaceJoin, "bind")
				if err != nil {
					return err
				}
				return ApplyBinds(ctx.Config, items)
			},
		},
		{
			Key:      "socksd",
			Surfaces: surfaceSet(SurfaceCLI, SurfaceJoin),
			Aliases:  aliasSet("socksd", SurfaceJoin),
			Apply: func(ctx *ApplyContext, op Operation) error {
				value, err := boolOp(op)
				if err != nil {
					return err
				}
				ctx.Config.EnableSocksServer = value
				return nil
			},
		},
		{
			Key:      "gateway",
			Surfaces: surfaceSet(SurfaceJoin),
			Aliases:  aliasSet("gateway", SurfaceJoin),
			Apply: func(ctx *ApplyContext, op Operation) error {
				value, err := boolOp(op)
				if err != nil {
					return err
				}
				ctx.Config.EnableProxyServer = value
				if value {
					ctx.Config.EnableSocksServer = true
				}
				return nil
			},
		},
		{
			Key:      "api",
			Surfaces: surfaceSet(SurfaceCLI, SurfaceJoin),
			Aliases:  aliasSet("api", SurfaceJoin),
			Apply: func(ctx *ApplyContext, op Operation) error {
				value, err := boolOp(op)
				if err != nil {
					return err
				}
				ctx.Config.EnableAPIServer = value
				return nil
			},
		},
		{
			Key:      "apiaddr",
			Surfaces: surfaceSet(SurfaceCLI, SurfaceJoin),
			Aliases:  aliasSet("apiaddr", SurfaceJoin),
			Apply: func(ctx *ApplyContext, op Operation) error {
				value, err := stringOp(op)
				if err != nil {
					return err
				}
				ctx.Config.APIServerAddr = value
				return nil
			},
		},
		{
			Key:      "diodeaddrs",
			Surfaces: surfaceSet(SurfaceCLI, SurfaceAPI, SurfaceJoin),
			Aliases:  aliasSet("diodeaddrs", SurfaceAPI, SurfaceJoin),
			Apply: func(ctx *ApplyContext, op Operation) error {
				items, err := stringListOp(op, ctx.Surface == SurfaceJoin, "diodeaddrs")
				if err != nil {
					return err
				}
				ApplyDiodeAddrs(ctx.Config, ctx.DefaultRemoteRPCAddrs, items)
				return nil
			},
		},
		{
			Key:          "fleet",
			Surfaces:     surfaceSet(SurfaceAPI, SurfaceJoin, SurfaceConfig),
			Aliases:      aliasSet("fleet", SurfaceAPI, SurfaceJoin, SurfaceConfig),
			Apply:        applyFleet,
			ExportConfig: exportFleet,
		},
		{
			Key:      "allowlists",
			Surfaces: surfaceSet(SurfaceCLI, SurfaceAPI, SurfaceJoin),
			Aliases:  aliasSet("allowlists", SurfaceAPI, SurfaceJoin),
			Apply: func(ctx *ApplyContext, op Operation) error {
				items, err := stringListOp(op, ctx.Surface == SurfaceJoin, "allowlists")
				if err != nil {
					return err
				}
				return ApplyAllowlist(ctx.Config, items)
			},
		},
		{
			Key:      "blocklists",
			Surfaces: surfaceSet(SurfaceCLI, SurfaceAPI, SurfaceJoin),
			Aliases:  aliasSet("blocklists", SurfaceAPI, SurfaceJoin),
			Apply: func(ctx *ApplyContext, op Operation) error {
				items, err := stringListOp(op, ctx.Surface == SurfaceJoin, "blocklists")
				if err != nil {
					return err
				}
				return ApplyBlocklist(ctx.Config, items)
			},
		},
		{
			Key:      "blockdomains",
			Surfaces: surfaceSet(SurfaceCLI, SurfaceJoin),
			Aliases:  aliasSet("blockdomains", SurfaceJoin),
			Apply: func(ctx *ApplyContext, op Operation) error {
				items, err := stringListOp(op, ctx.Surface == SurfaceJoin, "blockdomains")
				if err != nil {
					return err
				}
				ctx.Config.SBlockdomains = config.StringValues(items)
				return nil
			},
		},
		{
			Key:      "debug",
			Surfaces: surfaceSet(SurfaceCLI, SurfaceJoin),
			Aliases:  aliasSet("debug", SurfaceJoin),
			Apply: func(ctx *ApplyContext, op Operation) error {
				value, err := boolOp(op)
				if err != nil {
					return err
				}
				ctx.Config.Debug = value
				return nil
			},
		},
		{
			Key:      "resolvecachetime",
			Surfaces: surfaceSet(SurfaceCLI, SurfaceJoin),
			Aliases: map[Surface][]string{
				SurfaceCLI:  {"resolvecachetime", "bnscachetime"},
				SurfaceJoin: {"resolvecachetime", "bnscachetime"},
			},
			Apply: func(ctx *ApplyContext, op Operation) error {
				value, err := durationOp(op)
				if err != nil {
					return err
				}
				ctx.Config.ResolveCacheTime = value
				ctx.Config.BnsCacheTime = value
				return nil
			},
		},
		{
			Key:      "dbpath",
			Surfaces: surfaceSet(SurfaceCLI, SurfaceJoin),
			Aliases:  aliasSet("dbpath", SurfaceJoin),
			Apply: func(ctx *ApplyContext, op Operation) error {
				value, err := stringOp(op)
				if err != nil {
					return err
				}
				ctx.Config.DBPath = value
				return nil
			},
		},
		{
			Key:      "e2etimeout",
			Surfaces: surfaceSet(SurfaceCLI, SurfaceJoin),
			Aliases:  aliasSet("e2etimeout", SurfaceJoin),
			Apply: func(ctx *ApplyContext, op Operation) error {
				value, err := durationOp(op)
				if err != nil {
					return err
				}
				ctx.Config.EdgeE2ETimeout = value
				return nil
			},
		},
		{
			Key:      "logdatetime",
			Surfaces: surfaceSet(SurfaceCLI, SurfaceJoin),
			Aliases:  aliasSet("logdatetime", SurfaceJoin),
			Apply: func(ctx *ApplyContext, op Operation) error {
				value, err := boolOp(op)
				if err != nil {
					return err
				}
				ctx.Config.LogDateTime = value
				return nil
			},
		},
		{
			Key:      "logfilepath",
			Surfaces: surfaceSet(SurfaceCLI, SurfaceJoin),
			Aliases:  aliasSet("logfilepath", SurfaceJoin),
			Apply: func(ctx *ApplyContext, op Operation) error {
				value, err := stringOp(op)
				if err != nil {
					return err
				}
				ctx.Config.LogFilePath = value
				return nil
			},
		},
		{
			Key:      "blockprofile",
			Surfaces: surfaceSet(SurfaceCLI, SurfaceJoin),
			Aliases:  aliasSet("blockprofile", SurfaceJoin),
			Apply: func(ctx *ApplyContext, op Operation) error {
				value, err := stringOp(op)
				if err != nil {
					return err
				}
				ctx.Config.BlockProfile = value
				return nil
			},
		},
		{
			Key:      "blockprofilerate",
			Surfaces: surfaceSet(SurfaceCLI, SurfaceJoin),
			Aliases: map[Surface][]string{
				SurfaceCLI:  {"blockprofilerate"},
				SurfaceJoin: {"blockprofilerate", "blockproliferate"},
			},
			Apply: func(ctx *ApplyContext, op Operation) error {
				value, err := intOp(op)
				if err != nil {
					return err
				}
				ctx.Config.BlockProfileRate = value
				return nil
			},
		},
		{
			Key:      "cpuprofile",
			Surfaces: surfaceSet(SurfaceCLI, SurfaceJoin),
			Aliases:  aliasSet("cpuprofile", SurfaceJoin),
			Apply: func(ctx *ApplyContext, op Operation) error {
				value, err := stringOp(op)
				if err != nil {
					return err
				}
				ctx.Config.CPUProfile = value
				return nil
			},
		},
		{
			Key:          "last_update_at",
			Surfaces:     surfaceSet(SurfaceConfig),
			Aliases:      aliasSet("last_update_at", SurfaceConfig),
			Apply:        applyLastUpdateAt,
			ExportConfig: exportLastUpdateAt,
		},
	}
}

func (r *Registry) ExportConfig(ctx *ApplyContext, unsafe bool) ([]ConfigListEntry, error) {
	var out []ConfigListEntry
	for _, desc := range r.descriptors {
		if !desc.Supports(SurfaceConfig) || desc.ExportConfig == nil {
			continue
		}
		entries, err := desc.ExportConfig(ctx, unsafe)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", desc.Key, err)
		}
		out = append(out, entries...)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Key < out[j].Key
	})
	return out, nil
}

func ApplyJoinProperties(registry *Registry, ctx *ApplyContext, props map[string]string) error {
	batch := NewBatch(SurfaceJoin)
	if _, ok := props["diodeaddrs"]; !ok {
		batch.Add("diodeaddrs", []string{})
	}
	for key, val := range props {
		if key == "extra_config" {
			extra, err := ParseExtraConfig(val)
			if err != nil {
				return fmt.Errorf("parse extra_config: %w", err)
			}
			for extraKey, extraVal := range extra {
				desc, ok := registry.Lookup(SurfaceJoin, extraKey)
				if !ok {
					if ctx.Config != nil && ctx.Config.Logger != nil {
						ctx.Config.Logger.Warn("Ignoring %s from extra_config: unsupported key", extraKey)
					}
					continue
				}
				batch.Add(desc.Key, extraVal)
			}
			continue
		}
		desc, ok := registry.Lookup(SurfaceJoin, key)
		if !ok {
			continue
		}
		batch.Add(desc.Key, joinScalarValue(desc.Key, val))
	}
	return registry.Apply(ctx, batch)
}

func surfaceSet(items ...Surface) map[Surface]bool {
	out := make(map[Surface]bool, len(items))
	for _, item := range items {
		out[item] = true
	}
	return out
}

func aliasSet(key string, extraSurfaces ...Surface) map[Surface][]string {
	out := map[Surface][]string{}
	for _, surface := range extraSurfaces {
		out[surface] = []string{key}
	}
	if _, ok := out[SurfaceCLI]; !ok {
		out[SurfaceCLI] = []string{key}
	}
	return out
}

func stringListOp(op Operation, splitJoin bool, key string) ([]string, error) {
	if op.Delete {
		return []string{}, nil
	}
	items, err := StringSliceFromValue(op.Value)
	if err != nil {
		return nil, err
	}
	if splitJoin && len(items) == 1 {
		return splitJoinList(key, items[0]), nil
	}
	return items, nil
}

func boolOp(op Operation) (bool, error) {
	if op.Delete {
		return false, nil
	}
	return BoolFromValue(op.Value)
}

func stringOp(op Operation) (string, error) {
	if op.Delete {
		return "", nil
	}
	return StringFromValue(op.Value)
}

func durationOp(op Operation) (time.Duration, error) {
	if op.Delete {
		return 0, nil
	}
	return DurationFromValue(op.Value)
}

func intOp(op Operation) (int, error) {
	if op.Delete {
		return 0, nil
	}
	return IntFromValue(op.Value)
}

func joinScalarValue(key string, raw string) string {
	trimmed := strings.TrimSpace(raw)
	switch key {
	case "api", "debug", "e2etimeout", "fleet", "gateway", "logdatetime", "resolvecachetime", "socksd", "blockprofilerate":
		if idx := indexWhitespace(trimmed); idx >= 0 {
			trimmed = trimmed[:idx]
		}
	}
	return trimmed
}

func splitJoinList(key string, raw string) []string {
	switch key {
	case "diodeaddrs", "allowlists", "blocklists", "blockdomains":
		return NormalizeList(strings.Split(raw, ","))
	case "bind", "public", "private", "protected", "sshd":
		return NormalizeList(strings.Fields(raw))
	default:
		return []string{raw}
	}
}

func indexWhitespace(raw string) int {
	for i, r := range raw {
		switch r {
		case ' ', '\t', '\r', '\n':
			return i
		}
	}
	return -1
}
