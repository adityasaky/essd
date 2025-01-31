package cat

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/adityasaky/essd/internal/dsse"
	"github.com/spf13/cobra"
)

type options struct {
	summaryOnly     bool
	payloadOnly     bool
	payloadTypeOnly bool
}

func (o *options) AddFlags(cmd *cobra.Command) {
	cmd.Flags().BoolVar(
		&o.summaryOnly,
		"summary",
		false,
		"summary of envelope",
	)

	cmd.Flags().BoolVarP(
		&o.payloadOnly,
		"payload",
		"p",
		false,
		"envelope payload",
	)

	cmd.Flags().BoolVarP(
		&o.payloadTypeOnly,
		"payload-type",
		"t",
		false,
		"envelope's payload type",
	)

	cmd.MarkFlagsMutuallyExclusive("summary", "payload", "payload-type")
}

func (o *options) Run(_ *cobra.Command, args []string) error {
	switch {
	case o.summaryOnly:
		return o.printSummary(args)
	case o.payloadOnly:
		return o.printPayload(args)
	case o.payloadTypeOnly:
		return o.printPayloadType(args)
	default:
		return o.printSummary(args)
	}
}

func (o *options) printSummary(args []string) error {
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

func (o *options) printPayload(args []string) error {
	for _, envPath := range args {
		envBytes, err := os.ReadFile(envPath)
		if err != nil {
			return err
		}
		env := &dsse.Envelope{}
		if err := json.Unmarshal(envBytes, env); err != nil {
			return err
		}
		fmt.Println(env.Payload)
	}
	return nil
}

func (o *options) printPayloadType(args []string) error {
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

func New() *cobra.Command {
	o := &options{}
	cmd := &cobra.Command{
		Use:   "cat",
		Short: "Concatenate specified parts of DSSE envelope",
		Args:  cobra.MinimumNArgs(1),
		RunE:  o.Run,
	}
	o.AddFlags(cmd)

	return cmd
}
