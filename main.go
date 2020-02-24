// Cozy-apps-registry is a web service that allows to list web applications and
// connectors that can be installed on a cozy instance.
package main

import (
	"fmt"
	"os"

	"github.com/cozy/cozy-apps-registry/cmd"
)

func main() {
	rootCmd, err := cmd.Root()
	if err != nil {
		err = rootCmd.Execute()
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err.Error())
		os.Exit(1)
	}
}
