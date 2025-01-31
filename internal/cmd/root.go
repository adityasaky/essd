package cmd

import (
	"github.com/adityasaky/essd/internal/cmd/cat"
	"github.com/adityasaky/essd/internal/cmd/sign"
	"github.com/adityasaky/essd/internal/cmd/verify"
	"github.com/spf13/cobra"
)

func New() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "essd",
		Short: "A tool to sign, verify, and inspect DSSE envelopes",
	}

	rootCmd.AddCommand(cat.New())
	rootCmd.AddCommand(sign.New())
	rootCmd.AddCommand(verify.New())

	return rootCmd
}
