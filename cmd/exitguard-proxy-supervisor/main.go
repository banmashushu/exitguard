// The owned helper has no standalone proxy/control interface.
package main

import (
	"exitguard/internal/managedproxy"
	"os"
)

func main() { os.Exit(managedproxy.RunSupervisor(os.Args[1:], os.Stdin)) }
