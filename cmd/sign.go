package cmd

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	"github.com/secure-systems-lab/go-securesystemslib/cjson"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/spf13/cobra"
)

var signCmd = &cobra.Command{
	Use:   "sign",
	Short: "Create signed envelope from arbitrary file",
	Args:  cobra.ExactArgs(1),
	RunE:  sign,
}

var signEnvCmd = &cobra.Command{
	Use:   "sign-envelope",
	Short: "Add signature to envelope",
	Args:  cobra.ExactArgs(1),
	RunE:  signEnvelope,
}

var (
	signingKey       string
	outputPath       string
	canonicalizeJson bool
	payloadType      string
)

func init() {
	signCmd.Flags().StringVarP(
		&signingKey,
		"key",
		"k",
		"",
		"Signing key",
	)
	signCmd.MarkFlagRequired("key") //nolint:errcheck

	signCmd.Flags().StringVarP(
		&keyType,
		"key-type",
		"t",
		"rsa",
		"Signing key type (supported: 'rsa', 'ed25519', 'ecdsa')",
	)

	signCmd.Flags().StringVarP(
		&outputPath,
		"output",
		"o",
		"",
		"Output path to write envelope",
	)

	signCmd.Flags().StringVarP(
		&payloadType,
		"payload-type",
		"p",
		"",
		"Payload type for DSSE envelope",
	)
	signCmd.MarkFlagRequired("payload-type") //nolint:errcheck

	signCmd.Flags().BoolVar(
		&canonicalizeJson,
		"canonicalize-json",
		false,
		"Encode as canonical JSON if target is a JSON file",
	)
}

func init() {
	signEnvCmd.Flags().StringVarP(
		&signingKey,
		"key",
		"k",
		"",
		"Signing key",
	)
	signEnvCmd.MarkFlagRequired("key") //nolint:errcheck

	signEnvCmd.Flags().StringVarP(
		&keyType,
		"key-type",
		"t",
		"rsa",
		"Signing key type (supported: 'rsa', 'ed25519', 'ecdsa')",
	)

	signEnvCmd.Flags().StringVarP(
		&outputPath,
		"output",
		"o",
		"",
		"Output path to write envelope",
	)
}

func sign(cmd *cobra.Command, args []string) error {
	payload, err := os.ReadFile(args[0])
	if err != nil {
		return err
	}

	if canonicalizeJson {
		jsonRepr := &map[string]any{}
		if err := json.Unmarshal(payload, jsonRepr); err != nil {
			return err
		}
		encodedBytes, err := cjson.EncodeCanonical(jsonRepr)
		if err != nil {
			return err
		}
		payload = encodedBytes
	}

	signer, _, err := getSignerVerifier(signingKey, keyType)
	if err != nil {
		return err
	}
	envSigner, err := dsse.NewEnvelopeSigner(signer)
	if err != nil {
		return err
	}

	env, err := envSigner.SignPayload(context.Background(), payloadType, payload)
	if err != nil {
		return err
	}

	envBytes, err := json.Marshal(env)
	if err != nil {
		return err
	}

	if len(outputPath) == 0 {
		outputPath = fmt.Sprintf("%s.dsse", args[0])
	}

	return os.WriteFile(outputPath, envBytes, 0644)
}

func signEnvelope(cmd *cobra.Command, args []string) error {
	envBytes, err := os.ReadFile(args[0])
	if err != nil {
		return err
	}
	env := &dsse.Envelope{}
	if err := json.Unmarshal(envBytes, env); err != nil {
		return err
	}
	payload, err := env.DecodeB64Payload()
	if err != nil {
		return err
	}

	signer, keyID, err := getSignerVerifier(signingKey, keyType)
	if err != nil {
		return err
	}

	signable := dsse.PAE(env.PayloadType, payload)
	signature, err := signer.Sign(context.Background(), signable)
	if err != nil {
		return err
	}
	env.Signatures = append(env.Signatures, dsse.Signature{KeyID: keyID, Sig: base64.StdEncoding.EncodeToString(signature)})

	envBytes, err = json.Marshal(env)
	if err != nil {
		return err
	}

	if len(outputPath) == 0 {
		outputPath = args[0]
	}

	return os.WriteFile(outputPath, envBytes, 0644)
}
