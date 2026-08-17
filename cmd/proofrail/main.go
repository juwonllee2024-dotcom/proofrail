package main

import (
	"fmt"
	"os"

	"github.com/proofrail/proofrail/internal/scanner"
)

func main() {
	if err := scanner.RunCLI(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "proofrail:", err)
		os.Exit(scanner.ExitCode(err))
	}
}
