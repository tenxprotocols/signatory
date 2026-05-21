// signatory-recovery-tool is an admin-only tool for unwrapping and re-wrapping
// the KMS-encrypted private key blobs that the Confidential Space signer
// persists to Firestore. It exists to support migrations between WIPs / KMS
// keys / Firestore databases and to recover keys to Tezos b58 format when
// absolutely necessary.
//
// The tool requires admin access to Google Cloud KMS (encrypter/decrypter on
// the relevant keys) — i.e., it deliberately bypasses the TEE attestation
// invariant. Use with care; audit logs will record every operation.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	root := &cobra.Command{
		Use:   "signatory-recovery-tool",
		Short: "Admin tool for unwrapping / re-wrapping Confidential Space encrypted-key blobs",
		Long: `Operates on the KMS-encrypted CBOR(PrivateKey) blobs that the
Confidential Space signer stores in Firestore. Bypasses the TEE — the caller's
own credentials are used for KMS decrypt/encrypt. Reserved for migrations and
emergency recovery.`,
	}

	root.AddCommand(newUnwrapCmd(), newRewrapCmd())

	if err := root.ExecuteContext(ctx); err != nil {
		os.Exit(1)
	}
}
