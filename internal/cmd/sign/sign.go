package sign

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"

	"github.com/adityasaky/essd/internal/dsse"
	"github.com/adityasaky/essd/internal/sigstore"
	"github.com/adityasaky/essd/internal/ssh"
	"github.com/secure-systems-lab/go-securesystemslib/cjson"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"
)

type options struct {
	sshKeyPath  string
	useSigstore bool

	payloadType string

	outputPath string

	canonicalizeJson bool
}

func (o *options) AddFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(
		&o.sshKeyPath,
		"key",
		"k",
		"",
		"path of SSH key to sign with",
	)

	cmd.Flags().BoolVar(
		&o.useSigstore,
		"sigstore",
		false,
		"sign with Sigstore",
	)

	cmd.MarkFlagsOneRequired("key", "sigstore")

	cmd.Flags().StringVarP(
		&o.payloadType,
		"payload-type",
		"t",
		"",
		"payload type for DSSE envelope",
	)

	cmd.Flags().StringVarP(
		&o.outputPath,
		"output",
		"o",
		"",
		"output path to write envelope",
	)

	cmd.Flags().BoolVar(
		&o.canonicalizeJson,
		"canonicalize-json",
		false,
		"encode payload using canonical JSON (specified payload MUST be JSON)",
	)
}

func (o *options) Run(cmd *cobra.Command, args []string) error {
	payload, err := os.ReadFile(args[0])
	if err != nil {
		return err
	}

	// Check if payload is already an envelope
	isEnvelope := false
	env := &dsse.Envelope{}
	var signable []byte
	if err := json.Unmarshal(payload, env); err == nil {
		slog.Debug("Envelope exists, adding signature...")
		isEnvelope = true
		envPayload, err := env.DecodeB64Payload()
		if err != nil {
			return err
		}
		signable = envPayload
	} else {
		slog.Debug("Creating new envelope...")
		signable = payload
		env = &dsse.Envelope{
			PayloadType: o.payloadType,
			Payload:     base64.StdEncoding.EncodeToString(signable),
			Signatures:  []dsse.Signature{},
		}
	}

	if isEnvelope {
		if o.canonicalizeJson {
			return fmt.Errorf("cannot use --canonicalize-json when signing existing DSSE envelope")
		}

		if o.outputPath != "" {
			return fmt.Errorf("cannot use --output when signing existing DSSE envelope")
		} else {
			o.outputPath = args[0]
		}

		if o.payloadType != "" {
			return fmt.Errorf("cannot use --payload-type when signing existing DSSE envelope")
		}
	} else {
		if o.payloadType == "" {
			return fmt.Errorf("required flag --payload-type not set for creating new DSSE envelope")
		}

		if o.outputPath == "" {
			o.outputPath = fmt.Sprintf("%s.dsse", args[0])
		}
	}

	if o.canonicalizeJson {
		jsonRepr := &map[string]any{}
		if err := json.Unmarshal(signable, jsonRepr); err != nil {
			return err
		}
		encodedBytes, err := cjson.EncodeCanonical(jsonRepr)
		if err != nil {
			return err
		}
		signable = encodedBytes
	}

	signer, err := o.getSigner()
	if err != nil {
		return err
	}

	pae := dsse.PAE(o.payloadType, signable)
	signature, err := signer.Sign(cmd.Context(), pae)
	if err != nil {
		return err
	}
	keyID, err := signer.KeyID()
	if err != nil {
		return err
	}

	if _, isSigstoreSigner := signer.(*sigstore.Signer); isSigstoreSigner {
		// Unpack the bundle to get the signature + verification material
		// Set extension in the signature object

		bundle := protobundle.Bundle{}
		if err := protojson.Unmarshal(signature, &bundle); err != nil {
			return err
		}

		actualSigBytes, err := protojson.Marshal(bundle.GetMessageSignature())
		if err != nil {
			return err
		}

		verificationMaterial := bundle.GetVerificationMaterial()
		verificationMaterialBytes, err := protojson.Marshal(verificationMaterial)
		if err != nil {
			return err
		}
		verificationMaterialStruct := new(structpb.Struct)
		if err := protojson.Unmarshal(verificationMaterialBytes, verificationMaterialStruct); err != nil {
			return err
		}

		env.Signatures = append(env.Signatures, dsse.Signature{
			Sig:   base64.StdEncoding.EncodeToString(actualSigBytes),
			KeyID: keyID,
			Extension: &dsse.Extension{
				Kind: sigstore.ExtensionMimeType,
				Ext:  verificationMaterialStruct,
			},
		})
	} else {
		env.Signatures = append(env.Signatures, dsse.Signature{
			KeyID: keyID,
			Sig:   base64.StdEncoding.EncodeToString(signature),
		})
	}

	envBytes, err := json.Marshal(env)
	if err != nil {
		return err
	}

	return os.WriteFile(o.outputPath, envBytes, 0o644)
}

func (o *options) getSigner() (dsse.Signer, error) {
	if o.useSigstore {
		return sigstore.NewSigner(), nil
	}
	return ssh.NewSignerFromFile(o.sshKeyPath)
}

func New() *cobra.Command {
	o := &options{}
	cmd := &cobra.Command{
		Use:   "sign",
		Short: "Create signed DSSE envelope for an arbitrary payload",
		Args:  cobra.ExactArgs(1),
		RunE:  o.Run,
	}
	o.AddFlags(cmd)

	return cmd
}
