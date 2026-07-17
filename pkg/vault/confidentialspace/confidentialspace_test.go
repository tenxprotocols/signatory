package confidentialspace

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"testing"

	"github.com/ecadlabs/gotez/v2/crypt"
	"github.com/ecadlabs/signatory/pkg/vault/confidentialspace/rpc"
)

func TestIsStaleHandleError(t *testing.T) {
	staleNested := &rpc.RPCError{Message: "signer error", Source: &rpc.RPCError{Message: "invalid handle"}}
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"unrelated error", errors.New("nope"), false},
		{"unrelated RPCError", &rpc.RPCError{Message: "unknown handle"}, false},
		{"top-level invalid handle", &rpc.RPCError{Message: "invalid handle"}, true},
		{"nested signer error", staleNested, true},
		{"case insensitive", &rpc.RPCError{Message: "Invalid Handle"}, true},
		{"deep nested", &rpc.RPCError{Message: "a", Source: &rpc.RPCError{Message: "b", Source: &rpc.RPCError{Message: "invalid handle"}}}, true},
		{"wrapped via fmt.Errorf %w", fmt.Errorf("(ConfidentialSpace): %w", staleNested), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isStaleHandleError(tc.err); got != tc.want {
				t.Errorf("isStaleHandleError(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// TestSignRecoversFromStaleHandle: when the tee-signer returns the
// stale-handle error chain (which happens after a restart wipes its
// handle table), the vault must re-Import the cached encrypted blob,
// update the handle in place, and retry Sign exactly once.
func TestSignRecoversFromStaleHandle(t *testing.T) {
	srv := startTableFakeServer(t)
	v := newTestVault(t, srv)

	keyA := genKey(t)
	blobA := []byte("blob-A")
	pubA := srv.Register(blobA, keyA)

	// Cached handle points nowhere: the table is empty.
	key, ref := addKey(v, pubA, 7, blobA)

	msg := []byte("test message")
	sig, err := ref.Sign(context.Background(), msg, signV2)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !pubA.VerifySignature(sig, msg) {
		t.Fatal("Sign returned a non-verifying signature")
	}
	if key.handle == 7 {
		t.Errorf("handle was not updated after reimport (still %d)", key.handle)
	}
	if got := srv.ImportCalls(); got != 1 {
		t.Errorf("server saw %d Import calls, want 1", got)
	}
}

// TestSignNoReimportWhenEncryptedKeyMissing: defensive path — if a key
// somehow lacks its cached encrypted blob, a stale-handle response
// surfaces an error instead of nil-derefing or hanging.
func TestSignNoReimportWhenEncryptedKeyMissing(t *testing.T) {
	srv := startTableFakeServer(t)
	v := newTestVault(t, srv)

	keyA := genKey(t)
	pubA := crypt.Ed25519PublicKey(keyA.Public().(ed25519.PublicKey))
	_, ref := addKey(v, pubA, 7, nil /* no cached blob */)

	_, err := ref.Sign(context.Background(), []byte("x"), signV2)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}
