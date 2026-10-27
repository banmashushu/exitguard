// Package nativeprobe records actual network operations. Failure may mean a
// closed listener, routing failure or a firewall; it is never called a pass.
package nativeprobe

import (
	"net"
	"time"
)

type Observation struct {
	Address   string `json:"address"`
	Connected bool   `json:"connected"`
	Error     string `json:"error,omitempty"`
}

func TCP(address string, timeout time.Duration) Observation {
	result := Observation{Address: address}
	connection, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	result.Connected = true
	connection.Close()
	return result
}
