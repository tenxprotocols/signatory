package main

import (
	"errors"
	"fmt"
	"os"

	tz "github.com/ecadlabs/gotez/v2"
	"github.com/ecadlabs/gotez/v2/crypt"
	"github.com/ecadlabs/signatory/pkg/vault/confidentialspace/rpc"
	"github.com/fxamacker/cbor/v2"
	"github.com/spf13/cobra"
)

func newUnwrapCmd() *cobra.Command {
	var (
		kmsKey       string
		blobFile     string
		blobBase64   string
		firestoreURI string
	)

	cmd := &cobra.Command{
		Use:           "unwrap",
		Short:         "Decrypt a Confidential Space blob and print the Tezos secret key as `unencrypted:<edsk|spsk|p2sk|BLsk...>`",
		SilenceUsage:  true,
		SilenceErrors: false,
		Long: `Decrypts a single KMS-wrapped CBOR(PrivateKey) blob and emits the Tezos b58
secret key in the form Signatory's file vault accepts:

    unencrypted:edsk3...

The plaintext exists in this process's memory between the KMS decrypt call and
the print. Prefer rewrap (no Tezos-format plaintext ever produced) when the
goal is migration; use unwrap only when you genuinely need the key in
file-vault form.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()

			ciphertext, err := readBlob(ctx, blobFile, blobBase64, firestoreURI)
			if err != nil {
				return fmt.Errorf("read blob: %w", err)
			}

			plaintext, err := kmsDecrypt(ctx, kmsKey, ciphertext)
			if err != nil {
				return err
			}
			defer zero(plaintext)

			var pk rpc.PrivateKey
			if err := cbor.Unmarshal(plaintext, &pk); err != nil {
				return fmt.Errorf("cbor decode plaintext: %w", err)
			}

			cryptPK, err := rpcToCryptPrivateKey(&pk)
			if err != nil {
				return err
			}

			b58 := cryptPK.ToBase58()
			pkh := cryptPK.Public().Hash().String()
			fmt.Fprintf(os.Stderr, "Public key hash: %s\n", pkh)
			fmt.Printf("unencrypted:%s\n", b58)
			return nil
		},
	}

	cmd.Flags().StringVar(&kmsKey, "kms-key", "",
		"Source KMS key path (projects/P/locations/L/keyRings/R/cryptoKeys/K) — required")
	cmd.Flags().StringVar(&blobFile, "blob", "",
		"Read blob bytes from this file (or '-' for stdin)")
	cmd.Flags().StringVar(&blobBase64, "blob-base64", "",
		"Read blob as a base64-encoded string (alternative to --blob)")
	cmd.Flags().StringVar(&firestoreURI, "from-firestore", "",
		"Read blob from Firestore: PROJECT/DATABASE[/COLLECTION]/PKH (COLLECTION defaults to encrypted_keys)")

	cmd.MarkFlagRequired("kms-key")
	cmd.MarkFlagsMutuallyExclusive("blob", "blob-base64", "from-firestore")

	return cmd
}

// rpcToCryptPrivateKey converts the wire-format Signatory→TEE PrivateKey (raw
// scalar bytes per curve) into a gotez crypt.PrivateKey suitable for
// MarshalText/Public.
func rpcToCryptPrivateKey(p *rpc.PrivateKey) (crypt.PrivateKey, error) {
	switch {
	case len(p.Ed25519) > 0:
		var k tz.Ed25519PrivateKey
		if len(p.Ed25519) != len(k) {
			return nil, fmt.Errorf("ed25519 seed wrong length: got %d, want %d", len(p.Ed25519), len(k))
		}
		copy(k[:], p.Ed25519)
		return crypt.NewPrivateKey(&k)

	case len(p.Secp256k1) > 0:
		var k tz.Secp256k1PrivateKey
		if len(p.Secp256k1) != len(k) {
			return nil, fmt.Errorf("secp256k1 scalar wrong length: got %d, want %d", len(p.Secp256k1), len(k))
		}
		copy(k[:], p.Secp256k1)
		return crypt.NewPrivateKey(&k)

	case len(p.P256) > 0:
		var k tz.P256PrivateKey
		if len(p.P256) != len(k) {
			return nil, fmt.Errorf("p256 scalar wrong length: got %d, want %d", len(p.P256), len(k))
		}
		copy(k[:], p.P256)
		return crypt.NewPrivateKey(&k)

	case len(p.BLS) > 0:
		var k tz.BLSPrivateKey
		if len(p.BLS) != len(k) {
			return nil, fmt.Errorf("bls scalar wrong length: got %d, want %d", len(p.BLS), len(k))
		}
		// tee-signer (Rust blst SecretKey::serialize) emits the scalar big-endian.
		// gotez's tz.BLSPrivateKey holds the scalar little-endian — that's what
		// goblst.ScalarFromBytes (=ScalarFromLEBytes) expects, matching the Tezos
		// b58 convention. Reverse byte order on the way in. Signatory's forward
		// path uses goblst.Scalar.BEBytes() to emit BE on the wire (see
		// pkg/vault/confidentialspace/rpc/types.go NewPrivateKey), so this is
		// the symmetric inverse of that serialization.
		for i := 0; i < len(p.BLS); i++ {
			k[i] = p.BLS[len(p.BLS)-1-i]
		}
		return crypt.NewPrivateKey(&k)

	default:
		return nil, errors.New("rpc PrivateKey has no curve bytes set")
	}
}
