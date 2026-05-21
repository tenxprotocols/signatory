package main

import (
	"fmt"
	"os"

	"github.com/ecadlabs/signatory/pkg/vault/confidentialspace/rpc"
	"github.com/fxamacker/cbor/v2"
	"github.com/spf13/cobra"
)

func newRewrapCmd() *cobra.Command {
	var (
		oldKMS       string
		newKMS       string
		blobFile     string
		blobBase64   string
		fromFirestoreURI string
		outFile      string
		outBase64    bool
		toFirestoreURI string
		pkhOverride  string
		verifyPKH    bool
	)

	cmd := &cobra.Command{
		Use:           "rewrap",
		Short:         "Decrypt a blob with --old-kms-key and re-encrypt with --new-kms-key, never producing a Tezos-format unencrypted key",
		SilenceUsage:  true,
		SilenceErrors: false,
		Long: `Reads a KMS-wrapped CBOR(PrivateKey) blob, decrypts it with --old-kms-key,
re-encrypts the (still CBOR-serialized) plaintext with --new-kms-key, and
writes the resulting ciphertext.

The CBOR plaintext exists in this process's memory between the two KMS calls
but is never decoded into a Tezos b58 secret key. The plaintext buffer is
zeroed on best-effort after re-encryption.

When --to-firestore is set, the doc id is taken from --pkh (or from the URI
trailing segment if --pkh is omitted). With --verify-pkh, the tool will CBOR-
decode the plaintext just to confirm the public key hash matches --pkh —
defense against routing a blob to the wrong document.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()

			ciphertext, err := readBlob(ctx, blobFile, blobBase64, fromFirestoreURI)
			if err != nil {
				return fmt.Errorf("read blob: %w", err)
			}

			plaintext, err := kmsDecrypt(ctx, oldKMS, ciphertext)
			if err != nil {
				return err
			}
			defer zero(plaintext)

			if verifyPKH {
				var pk rpc.PrivateKey
				if err := cbor.Unmarshal(plaintext, &pk); err != nil {
					return fmt.Errorf("cbor decode (for --verify-pkh): %w", err)
				}
				cryptPK, err := rpcToCryptPrivateKey(&pk)
				if err != nil {
					return fmt.Errorf("convert (for --verify-pkh): %w", err)
				}
				got := cryptPK.Public().Hash().String()
				if pkhOverride == "" {
					return fmt.Errorf("--verify-pkh requires --pkh to compare against (got pkh=%s)", got)
				}
				if got != pkhOverride {
					return fmt.Errorf("pkh mismatch: blob has %s, --pkh says %s", got, pkhOverride)
				}
				fmt.Fprintf(os.Stderr, "Verified PKH: %s\n", got)
			}

			newCiphertext, err := kmsEncrypt(ctx, newKMS, plaintext)
			if err != nil {
				return err
			}

			return writeBlob(ctx, outFile, toFirestoreURI, pkhOverride, outBase64, newCiphertext)
		},
	}

	cmd.Flags().StringVar(&oldKMS, "old-kms-key", "",
		"Source KMS key path (encrypter/decrypter on this key required) — required")
	cmd.Flags().StringVar(&newKMS, "new-kms-key", "",
		"Destination KMS key path (encrypter on this key required) — required")

	cmd.Flags().StringVar(&blobFile, "blob", "",
		"Read blob bytes from this file (or '-' for stdin)")
	cmd.Flags().StringVar(&blobBase64, "blob-base64", "",
		"Read blob as a base64-encoded string")
	cmd.Flags().StringVar(&fromFirestoreURI, "from-firestore", "",
		"Read blob from Firestore: PROJECT/DATABASE[/COLLECTION]/PKH")

	cmd.Flags().StringVar(&outFile, "out", "",
		"Write new ciphertext to this file (or '-' for stdout). Default stdout.")
	cmd.Flags().BoolVar(&outBase64, "out-base64", false,
		"Emit new ciphertext base64-encoded (file/stdout only).")
	cmd.Flags().StringVar(&toFirestoreURI, "to-firestore", "",
		"Write new ciphertext to Firestore: PROJECT/DATABASE[/COLLECTION][/PKH]. Doc id taken from --pkh if URI omits it.")

	cmd.Flags().StringVar(&pkhOverride, "pkh", "",
		"Public key hash for the doc id and pkh field when writing to Firestore.")
	cmd.Flags().BoolVar(&verifyPKH, "verify-pkh", false,
		"CBOR-decode the plaintext to verify the public key hash matches --pkh before re-encryption.")

	cmd.MarkFlagRequired("old-kms-key")
	cmd.MarkFlagRequired("new-kms-key")
	cmd.MarkFlagsMutuallyExclusive("blob", "blob-base64", "from-firestore")
	cmd.MarkFlagsMutuallyExclusive("out", "to-firestore")

	return cmd
}
