//go:build !windows || !amd64

package main

func dnsObservations(string) any { return map[string]string{"state": "unavailable"} }
