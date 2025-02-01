//go:generate go run .

package main

import (
	"fmt"
	"os"

	"github.com/adityasaky/essd/internal/cmd"
	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
)

var (
	dir    string
	genCmd = &cobra.Command{
		Use:   "gendoc",
		Short: "Generate help docs",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			return doc.GenMarkdownTree(cmd.New(), dir)
		},
	}
)

func init() {
	genCmd.Flags().StringVarP(&dir, "dir", "d", ".", "Path to directory in which to generate docs")
}

func main() {
	if err := genCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
