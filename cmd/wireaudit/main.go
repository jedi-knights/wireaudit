// Command wireaudit probes a live HTTP/HTTPS API and reports RFC-level
// protocol conformance findings.
package main

import (
	"context"
	"os"

	"github.com/jedi-knights/wireaudit/internal/cli"
)

func main() {
	os.Exit(cli.Run(context.Background(), os.Args[1:], os.Stdout, os.Stderr))
}
