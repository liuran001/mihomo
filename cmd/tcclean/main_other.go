//go:build !linux

// tcclean manipulates TC filters and qdiscs through netlink, which only
// exists on Linux; this stub keeps the package buildable elsewhere so
// `go test ./...` does not fail on other platforms.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "tcclean is only supported on Linux")
	os.Exit(1)
}
