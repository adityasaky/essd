package verify

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/adityasaky/essd/internal/dsse"
	"github.com/adityasaky/essd/internal/sigstore"
	"github.com/adityasaky/essd/internal/ssh"
	"github.com/spf13/cobra"
)

type options struct {
	publicKeys []string
}

func (o *options) AddFlags(cmd *cobra.Command) {
	cmd.Flags().StringArrayVarP(
		&o.publicKeys,
		"key",
		"k",
		nil,
		"key to use for verifying signatures (specify sigstore using fulcio:<identity>::<issuer>)",
	)
	cmd.MarkFlagRequired("key") //nolint:errcheck
}

func (o *options) Run(cmd *cobra.Command, args []string) error {
	envBytes, err := os.ReadFile(args[0])
	if err != nil {
		return err
	}
	env := &dsse.Envelope{}
	if err := json.Unmarshal(envBytes, env); err != nil {
		return err
	}

	verifiers, err := o.getVerifiers()
	if err != nil {
		return err
	}

	envVerifier, err := dsse.NewMultiEnvelopeVerifier(1, verifiers...)
	if err != nil {
		return err
	}

	_, err = envVerifier.Verify(cmd.Context(), env)
	return err
}

func (o *options) getVerifiers() ([]dsse.Verifier, error) {
	verifiers := []dsse.Verifier{}

	for _, key := range o.publicKeys {
		if strings.HasPrefix(key, "fulcio:") {
			key = strings.TrimPrefix(strings.TrimSpace(key), "fulcio:")
			keySplit := strings.Split(key, "::")
			if len(keySplit) != 2 {
				return nil, fmt.Errorf("invalid fulcio format: %s", key)
			}
			verifier := sigstore.NewVerifierFromIdentityAndIssuer(keySplit[0], keySplit[1])
			verifiers = append(verifiers, verifier)
		} else {
			sslibKey, err := ssh.NewKeyFromFile(key)
			if err != nil {
				return nil, fmt.Errorf("unable to load '%s': %w", key, err)
			}
			verifier, err := ssh.NewVerifierFromKey(sslibKey)
			if err != nil {
				return nil, fmt.Errorf("unable to load '%s': %w", key, err)
			}
			verifiers = append(verifiers, verifier)
		}
	}

	return verifiers, nil
}

func New() *cobra.Command {
	o := &options{}
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify signatures in DSSE envelope using specified keys",
		Args:  cobra.MinimumNArgs(1),
		RunE:  o.Run,
	}
	o.AddFlags(cmd)

	return cmd
}
