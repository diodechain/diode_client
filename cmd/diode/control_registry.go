package main

import (
	"sync"

	"github.com/diodechain/diode_client/cmd/diode/internal/control"
	"github.com/diodechain/diode_client/config"
	"github.com/diodechain/diode_client/db"
	"github.com/diodechain/diode_client/rpc"
	"github.com/diodechain/diode_client/util"
)

var (
	controlRegistryOnce sync.Once
	controlRegistry     *control.Registry
)

func getControlRegistry() *control.Registry {
	controlRegistryOnce.Do(func() {
		controlRegistry = control.NewRegistry(control.DefaultDescriptors())
	})
	return controlRegistry
}

func defaultRemoteRPCAddrs() []string {
	out := make([]string, len(bootDiodeAddrs))
	copy(out, bootDiodeAddrs[:])
	return out
}

func applyControlBatch(surface control.Surface, batch *control.Batch) error {
	ctx := &control.ApplyContext{
		Surface:               surface,
		Config:                config.AppConfig,
		DB:                    db.DB,
		DefaultRemoteRPCAddrs: defaultRemoteRPCAddrs(),
		Resolver:              currentControlResolver(),
	}
	return getControlRegistry().Apply(ctx, batch)
}

func applyJoinControlProps(props map[string]string) error {
	ctx := &control.ApplyContext{
		Surface:               control.SurfaceJoin,
		Config:                config.AppConfig,
		DB:                    db.DB,
		DefaultRemoteRPCAddrs: defaultRemoteRPCAddrs(),
		Resolver:              currentControlResolver(),
	}
	return control.ApplyJoinProperties(getControlRegistry(), ctx, props)
}

func currentControlResolver() control.Resolver {
	if app.clientManager == nil {
		return nil
	}
	client := app.clientManager.GetNearestClient()
	if client == nil {
		return nil
	}
	return controlResolver{client: client}
}

type controlResolver struct {
	client *rpc.Client
}

func (r controlResolver) ResolveBNSPeers(name string) error {
	_, err := r.client.GetCacheOrResolvePeers(name)
	return err
}

func (r controlResolver) ResolveAddressType(addr util.Address) (string, error) {
	return r.client.ResolveAccountType(addr)
}

func (r controlResolver) WarmPeers(addr util.Address) error {
	_, err := r.client.GetCacheOrResolveAllPeersOfAddrs(addr)
	return err
}
