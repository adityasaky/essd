package cmd

import (
	"context"
	"encoding/json"
	"os"

	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/spf13/cobra"
)

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify DSSE signature using a local public key",
	Args:  cobra.ExactArgs(1),
	RunE:  verify,
}

var publicKey string

func init() {
	verifyCmd.Flags().StringVarP(
		&publicKey,
		"key",
		"k",
		"",
		"Path to public key",
	)
	verifyCmd.MarkFlagRequired("key") //nolint:errcheck

	verifyCmd.Flags().StringVarP(
		&keyType,
		"key-type",
		"t",
		"rsa",
		"Type of public key",
	)
}

func verify(cmd *cobra.Command, args []string) error {
	envBytes, err := os.ReadFile(args[0])
	if err != nil {
		return err
	}
	env := &dsse.Envelope{}
	if err := json.Unmarshal(envBytes, env); err != nil {
		return err
	}

	verifier, _, err := getSignerVerifier(publicKey, keyType)
	if err != nil {
		return err
	}

	envVerifier, err := dsse.NewEnvelopeVerifier(verifier)
	if err != nil {
		return err
	}

	_, err = envVerifier.Verify(context.Background(), env)
	return err
}
