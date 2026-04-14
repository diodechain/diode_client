package control

import (
	"fmt"

	"github.com/diodechain/diode_client/config"
)

type Surface string

const (
	SurfaceCLI    Surface = "cli"
	SurfaceAPI    Surface = "api"
	SurfaceJoin   Surface = "join"
	SurfaceConfig Surface = "config"
)

type DB interface {
	Get(key string) ([]byte, error)
	Put(key string, value []byte) error
	Del(key string) error
	List() []string
}

type ApplyContext struct {
	Surface               Surface
	Config                *config.Config
	DB                    DB
	DefaultRemoteRPCAddrs []string
	Resolver              Resolver
}

type Operation struct {
	Key    string
	Value  interface{}
	Delete bool
}

type Batch struct {
	Surface Surface
	ops     []Operation
}

func NewBatch(surface Surface) *Batch {
	return &Batch{Surface: surface}
}

func (b *Batch) Add(key string, value interface{}) {
	b.ops = append(b.ops, Operation{Key: key, Value: value})
}

func (b *Batch) Delete(key string) {
	b.ops = append(b.ops, Operation{Key: key, Delete: true})
}

func (b *Batch) Ops() []Operation {
	if b == nil {
		return nil
	}
	ops := make([]Operation, len(b.ops))
	copy(ops, b.ops)
	return ops
}

type ConfigListEntry struct {
	Key   string
	Value string
}

type Descriptor struct {
	Key          string
	Surfaces     map[Surface]bool
	Aliases      map[Surface][]string
	Apply        func(ctx *ApplyContext, op Operation) error
	ExportConfig func(ctx *ApplyContext, unsafe bool) ([]ConfigListEntry, error)
}

func (d Descriptor) Supports(surface Surface) bool {
	return d.Surfaces[surface]
}

func (d Descriptor) AliasesFor(surface Surface) []string {
	return d.Aliases[surface]
}

type Registry struct {
	descriptors []Descriptor
	byKey       map[string]Descriptor
	byAlias     map[Surface]map[string]Descriptor
}

func NewRegistry(descriptors []Descriptor) *Registry {
	r := &Registry{
		descriptors: make([]Descriptor, len(descriptors)),
		byKey:       make(map[string]Descriptor, len(descriptors)),
		byAlias:     make(map[Surface]map[string]Descriptor),
	}
	copy(r.descriptors, descriptors)
	for _, desc := range r.descriptors {
		r.byKey[desc.Key] = desc
		for surface, aliases := range desc.Aliases {
			if r.byAlias[surface] == nil {
				r.byAlias[surface] = make(map[string]Descriptor)
			}
			for _, alias := range aliases {
				r.byAlias[surface][alias] = desc
			}
		}
	}
	return r
}

func (r *Registry) Descriptor(key string) (Descriptor, bool) {
	desc, ok := r.byKey[key]
	return desc, ok
}

func (r *Registry) Lookup(surface Surface, alias string) (Descriptor, bool) {
	if aliases := r.byAlias[surface]; aliases != nil {
		desc, ok := aliases[alias]
		return desc, ok
	}
	return Descriptor{}, false
}

func (r *Registry) AddByAlias(batch *Batch, alias string, value interface{}) error {
	if batch == nil {
		return fmt.Errorf("nil batch")
	}
	desc, ok := r.Lookup(batch.Surface, alias)
	if !ok {
		return fmt.Errorf("unknown %s key %q", batch.Surface, alias)
	}
	batch.Add(desc.Key, value)
	return nil
}

func (r *Registry) DeleteByAlias(batch *Batch, alias string) error {
	if batch == nil {
		return fmt.Errorf("nil batch")
	}
	desc, ok := r.Lookup(batch.Surface, alias)
	if !ok {
		return fmt.Errorf("unknown %s key %q", batch.Surface, alias)
	}
	batch.Delete(desc.Key)
	return nil
}

func (r *Registry) Apply(ctx *ApplyContext, batch *Batch) error {
	if ctx == nil || batch == nil {
		return nil
	}
	for _, op := range batch.ops {
		desc, ok := r.byKey[op.Key]
		if !ok {
			return fmt.Errorf("unknown key %q", op.Key)
		}
		if !desc.Supports(ctx.Surface) {
			return fmt.Errorf("key %q is not supported on %s", desc.Key, ctx.Surface)
		}
		if err := desc.Apply(ctx, op); err != nil {
			return fmt.Errorf("%s: %w", desc.Key, err)
		}
	}
	return nil
}
