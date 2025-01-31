package main

import (
	"os"

	"github.com/adityasaky/essd/internal/cmd"
)

func main() {
	rootCmd := cmd.New()
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}
