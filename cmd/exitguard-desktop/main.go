package main

import (
	"fmt"
	"os"

	"exitguard/internal/desktop"
)

func main() {
	if err := desktop.Run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "ExitGuard:", err)
		os.Exit(1)
	}
}
