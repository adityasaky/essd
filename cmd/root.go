package cmd

import (
	"os"

	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/secure-systems-lab/go-securesystemslib/signerverifier"
	"github.com/spf13/cobra"
)

var keyType string

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "essd",
	Short: "A tool to sign and verify DSSE envelopes",
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.AddCommand(signCmd)
	rootCmd.AddCommand(signEnvCmd)
	rootCmd.AddCommand(verifyCmd)
}

func getSignerVerifier(signingKey string, signingKeyType string) (dsse.SignerVerifier, string, error) {
	var signer dsse.SignerVerifier
	switch signingKeyType {
	case "rsa":
		key, err := signerverifier.LoadRSAPSSKeyFromFile(signingKey)
		if err != nil {
			return nil, "", err
		}
		signer, err = signerverifier.NewRSAPSSSignerVerifierFromSSLibKey(key)
		if err != nil {
			return nil, "", err
		}
	case "ed25519":
		key, err := signerverifier.LoadED25519KeyFromFile(signingKey)
		if err != nil {
			return nil, "", err
		}
		signer, err = signerverifier.NewED25519SignerVerifierFromSSLibKey(key)
		if err != nil {
			return nil, "", err
		}
	case "ecdsa":
		key, err := signerverifier.LoadECDSAKeyFromFile(signingKey)
		if err != nil {
			return nil, "", err
		}
		signer, err = signerverifier.NewECDSASignerVerifierFromSSLibKey(key)
		if err != nil {
			return nil, "", err
		}
	}

	keyID, err := signer.KeyID()
	if err != nil {
		return nil, "", err
	}

	return signer, keyID, nil
}
