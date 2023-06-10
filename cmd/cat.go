package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/spf13/cobra"
)

var catCmd = &cobra.Command{
	Use:   "cat",
	Short: "Concatenate specified parts of one or more DSSE envelopes to stdout",
}

var catPayloadCmd = &cobra.Command{
	Use:   "payload",
	Args:  cobra.MinimumNArgs(1),
	Short: "Concatenate envelope(s) payload to stdout",
	RunE:  catPayload,
}

var catPayloadTypeCmd = &cobra.Command{
	Use:   "payload-type",
	Args:  cobra.MinimumNArgs(1),
	Short: "Concatenate envelope(s) payload types to stdout",
	RunE:  catPayloadType,
}

var catSummaryCmd = &cobra.Command{
	Use:   "summary",
	Args:  cobra.MinimumNArgs(1),
	Short: "Print summary of envelope(s) to stdout",
	RunE:  catSummary,
}

var decodeB64 bool

func init() {
	catPayloadCmd.Flags().BoolVarP(
		&decodeB64,
		"decode-base64",
		"d",
		false,
		"Decode base64 encoded payload",
	)

	catCmd.AddCommand(catPayloadCmd)
	catCmd.AddCommand(catPayloadTypeCmd)
	catCmd.AddCommand(catSummaryCmd)
}

func catPayload(cmd *cobra.Command, args []string) error {
	for _, envPath := range args {
		envBytes, err := os.ReadFile(envPath)
		if err != nil {
			return err
		}
		env := &dsse.Envelope{}
		if err := json.Unmarshal(envBytes, env); err != nil {
			return err
		}
		if decodeB64 {
			decodedBytes, err := env.DecodeB64Payload()
			if err != nil {
				return err
			}
			fmt.Println(string(decodedBytes))
		} else {
			fmt.Println(env.Payload)
		}
	}
	return nil
}

func catPayloadType(cmd *cobra.Command, args []string) error {
	for _, envPath := range args {
		envBytes, err := os.ReadFile(envPath)
		if err != nil {
			return err
		}
		env := &dsse.Envelope{}
		if err := json.Unmarshal(envBytes, env); err != nil {
			return err
		}
		fmt.Println(env.PayloadType)
	}

	return nil
}

func catSummary(cmd *cobra.Command, args []string) error {
	for _, envPath := range args {
		envBytes, err := os.ReadFile(envPath)
		if err != nil {
			return err
		}
		env := &dsse.Envelope{}
		if err := json.Unmarshal(envBytes, env); err != nil {
			return err
		}

		signatureKeyIDs := []string{}
		signaturesWithoutKeyIDs := 0
		for _, s := range env.Signatures {
			if len(s.KeyID) == 0 {
				signaturesWithoutKeyIDs += 1
			} else {
				signatureKeyIDs = append(signatureKeyIDs, s.KeyID)
			}
		}

		fmt.Printf("Summary for %s:\n", envPath)
		fmt.Printf("\tPayload Type: %s\n", env.PayloadType)
		fmt.Printf("\tSignatures without key IDs: %d\n", signaturesWithoutKeyIDs)
		if len(signatureKeyIDs) > 0 {
			fmt.Printf("\tSignatures from declared key IDs:\n")
			for _, keyID := range signatureKeyIDs {
				fmt.Printf("\t\t%s\n", keyID)
			}
		}
	}

	return nil
}
