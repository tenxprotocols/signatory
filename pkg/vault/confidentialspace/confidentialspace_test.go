package confidentialspace

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"testing"

	"github.com/ecadlabs/gotez/v2/crypt"
	"github.com/ecadlabs/signatory/pkg/utils"
	"github.com/ecadlabs/signatory/pkg/vault"
	"github.com/ecadlabs/signatory/pkg/vault/confidentialspace/rpc"
	"github.com/fxamacker/cbor/v2"
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

// staleHandleFakeServer drives the regression path: the first Sign call
// returns the tee-signer's "stale handle" error chain; an Import then
// allocates a fresh handle; subsequent Sign calls with the new handle
// succeed. Mirrors how the real tee-signer behaves after a VM restart.
type staleHandleFakeServer struct {
	t              *testing.T
	ln             net.Listener
	handle         atomic.Uint64
	staleHandle    uint64
	importCalls    atomic.Int32
	signOk         atomic.Int32
	signStaleSeen  atomic.Int32
}

func startStaleHandleFakeServer(t *testing.T, staleHandle uint64) *staleHandleFakeServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &staleHandleFakeServer{t: t, ln: ln, staleHandle: staleHandle}
	t.Cleanup(func() { _ = ln.Close() })
	go s.serve()
	return s
}

func (s *staleHandleFakeServer) Addr() string { return s.ln.Addr().String() }

func (s *staleHandleFakeServer) serve() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handle1(conn)
	}
}

func (s *staleHandleFakeServer) handle1(conn net.Conn) {
	defer conn.Close()
	for {
		var lenBuf [4]byte
		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			return
		}
		n := binary.BigEndian.Uint32(lenBuf[:])
		body := make([]byte, n)
		if _, err := io.ReadFull(conn, body); err != nil {
			return
		}
		var req rpc.Request[rpc.ConfidentialSpaceCredentials]
		if err := cbor.Unmarshal(body, &req); err != nil {
			s.t.Errorf("server: bad cbor: %v", err)
			return
		}

		var respBytes []byte
		var err error
		switch {
		case req.Initialize != nil:
			respBytes, err = cbor.Marshal(&rpc.Result[*struct{}]{Ok: &struct{}{}})
		case req.Sign != nil:
			if req.Sign.Handle == s.staleHandle {
				s.signStaleSeen.Add(1)
				respBytes, err = cbor.Marshal(&rpc.Result[*rpc.Signature]{
					Err: &rpc.RPCError{
						Message: "signer error",
						Source:  &rpc.RPCError{Message: "invalid handle"},
					},
				})
			} else {
				s.signOk.Add(1)
				respBytes, err = cbor.Marshal(&rpc.Result[*rpc.Signature]{
					Ok: &rpc.Signature{Ed25519: make([]byte, 64)},
				})
			}
		case req.Import != nil:
			s.importCalls.Add(1)
			newHandle := s.handle.Add(1) + s.staleHandle // ensure != staleHandle
			respBytes, err = cbor.Marshal(&rpc.Result[*rpc.ImportResult]{
				Ok: &rpc.ImportResult{
					Handle:    newHandle,
					PublicKey: rpc.PublicKey{Ed25519: make([]byte, 32)},
				},
			})
		default:
			s.t.Errorf("server: unexpected request: %+v", req)
			return
		}
		if err != nil {
			s.t.Errorf("server: marshal: %v", err)
			return
		}

		out := make([]byte, 4+len(respBytes))
		binary.BigEndian.PutUint32(out, uint32(len(respBytes)))
		copy(out[4:], respBytes)
		if _, err := conn.Write(out); err != nil {
			return
		}
	}
}

// TestSignRecoversFromStaleHandle: when the tee-signer returns the
// stale-handle error chain (which happens after a VM restart), the
// vault must transparently re-Import the cached encrypted blob, update
// the handle in place, and retry Sign exactly once.
func TestSignRecoversFromStaleHandle(t *testing.T) {
	const staleHandle = uint64(7)

	srv := startStaleHandleFakeServer(t, staleHandle)
	dial := func(ctx context.Context) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", srv.Addr())
	}
	cli := rpc.NewClient(dial, &rpc.ConfidentialSpaceCredentials{WipProviderPath: "p", EncryptionKeyPath: "k"})
	t.Cleanup(func() { _ = cli.Close() })
	if err := cli.Connect(context.Background()); err != nil {
		t.Fatalf("Connect: %v", err)
	}

	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	pub := crypt.Ed25519PublicKey(edPub)

	key := &confidentialKey{
		pub:          pub,
		handle:       staleHandle,
		encryptedKey: []byte("fake-encrypted-blob"),
	}
	v := &ConfidentialSpaceVault[rpc.ConfidentialSpaceCredentials]{
		client: cli,
		keys:   []*confidentialKey{key},
	}
	ref := &confidentialKeyRef[rpc.ConfidentialSpaceCredentials]{
		confidentialKey: key,
		v:               v,
	}

	sig, err := ref.Sign(context.Background(), []byte("test message"), &vault.SignOptions{Version: utils.SigningVersion1})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if sig == nil {
		t.Fatal("Sign returned nil signature")
	}
	if key.handle == staleHandle {
		t.Errorf("handle was not updated after reimport (still %d)", key.handle)
	}
	if got := srv.signStaleSeen.Load(); got != 1 {
		t.Errorf("server saw %d sign calls with stale handle, want 1", got)
	}
	if got := srv.importCalls.Load(); got != 1 {
		t.Errorf("server saw %d Import calls, want 1", got)
	}
	if got := srv.signOk.Load(); got != 1 {
		t.Errorf("server saw %d successful sign calls, want 1", got)
	}
}

// TestSignNoReimportWhenEncryptedKeyMissing: defensive path — if a key
// somehow lacks its cached encrypted blob, a stale-handle response
// surfaces an error instead of nil-derefing or hanging.
func TestSignNoReimportWhenEncryptedKeyMissing(t *testing.T) {
	const staleHandle = uint64(7)

	srv := startStaleHandleFakeServer(t, staleHandle)
	dial := func(ctx context.Context) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", srv.Addr())
	}
	cli := rpc.NewClient(dial, &rpc.ConfidentialSpaceCredentials{WipProviderPath: "p", EncryptionKeyPath: "k"})
	t.Cleanup(func() { _ = cli.Close() })
	if err := cli.Connect(context.Background()); err != nil {
		t.Fatalf("Connect: %v", err)
	}

	edPub, _, _ := ed25519.GenerateKey(rand.Reader)
	pub := crypt.Ed25519PublicKey(edPub)

	key := &confidentialKey{pub: pub, handle: staleHandle /* encryptedKey deliberately nil */}
	v := &ConfidentialSpaceVault[rpc.ConfidentialSpaceCredentials]{client: cli, keys: []*confidentialKey{key}}
	ref := &confidentialKeyRef[rpc.ConfidentialSpaceCredentials]{confidentialKey: key, v: v}

	_, err := ref.Sign(context.Background(), []byte("x"), &vault.SignOptions{Version: utils.SigningVersion1})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}
