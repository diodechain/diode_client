package rpc

import (
	"sync"
)

// Devices keep the connected devices
type Devices struct {
	connectedDevice map[string]*ConnectedDevice
	rw              sync.RWMutex
}

func (d *Devices) GetDevice(k string) *ConnectedDevice {
	d.rw.RLock()
	defer d.rw.RUnlock()
	return d.connectedDevice[k]
}

func (d *Devices) SetDevice(k string, ud *ConnectedDevice) {
	d.rw.Lock()
	defer d.rw.Unlock()
	d.connectedDevice[k] = ud
	return
}

func (d *Devices) DelDevice(k string) {
	d.rw.Lock()
	defer d.rw.Unlock()
	delete(d.connectedDevice, k)
	return
}

func (d *Devices) FindDeviceByRef(ref int64) *ConnectedDevice {
	d.rw.RLock()
	defer d.rw.RUnlock()
	clientID := ""
	for d, r := range d.connectedDevice {
		if r.Ref == ref {
			clientID = d
			break
		}
	}
	return d.connectedDevice[clientID]
}
