package rpc

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/ecadlabs/signatory/pkg/utils"
	"github.com/ecadlabs/signatory/pkg/vault"
	"github.com/fxamacker/cbor/v2"
)

func TestIsConnError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"context.Canceled", context.Canceled, false},
		{"plain", errors.New("plain"), false},
		{"io.EOF", io.EOF, true},
		{"io.ErrUnexpectedEOF", io.ErrUnexpectedEOF, true},
		{"wrapped EOF", fmt.Errorf("read: %w", io.EOF), true},
		{"net.ErrClosed", net.ErrClosed, true},
		{"EPIPE", syscall.EPIPE, true},
		{"ECONNRESET", syscall.ECONNRESET, true},
		{"net.OpError", &net.OpError{Op: "write", Err: syscall.EPIPE}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isConnError(tc.err); got != tc.want {
				t.Errorf("isConnError(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// fakeServerBehavior controls how a fake-server connection handles
// requests. Connections beyond the configured behaviors default to
// serveAll.
type fakeServerBehavior int

const (
	serveAll fakeServerBehavior = iota
	// closeAfterInit: respond once (to Initialize) and then close.
	// Simulates a peer that has restarted between RPCs.
	closeAfterInit
	// signReturnsAppError: handle Initialize, then return an
	// application-level RPCError on Sign requests.
	signReturnsAppError
)

type fakeServer struct {
	t          *testing.T
	ln         net.Listener
	behaviors  []fakeServerBehavior
	conns      atomic.Int32
	requests   atomic.Int32
	signCalls  atomic.Int32
	importCalls atomic.Int32
}

func startFakeServer(t *testing.T, behaviors []fakeServerBehavior) *fakeServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &fakeServer{t: t, ln: ln, behaviors: behaviors}
	t.Cleanup(func() { _ = ln.Close() })
	go s.serve()
	return s
}

func (s *fakeServer) Addr() string { return s.ln.Addr().String() }

func (s *fakeServer) serve() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		idx := int(s.conns.Add(1)) - 1
		b := serveAll
		if idx < len(s.behaviors) {
			b = s.behaviors[idx]
		}
		go s.handle(conn, b)
	}
}

func (s *fakeServer) handle(conn net.Conn, b fakeServerBehavior) {
	defer conn.Close()
	for {
		var lenBuf [4]byte
		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			return
		}
		n := binary.BigEndian.Uint32(lenBuf[:])
		if n == 0 || n > 1<<20 {
			return
		}
		body := make([]byte, n)
		if _, err := io.ReadFull(conn, body); err != nil {
			return
		}
		s.requests.Add(1)

		var req Request[ConfidentialSpaceCredentials]
		if err := cbor.Unmarshal(body, &req); err != nil {
			s.t.Errorf("server: bad cbor: %v", err)
			return
		}

		var respBytes []byte
		var err error
		switch {
		case req.Initialize != nil:
			respBytes, err = cbor.Marshal(&Result[*struct{}]{Ok: &struct{}{}})
		case req.Sign != nil:
			s.signCalls.Add(1)
			if b == signReturnsAppError {
				respBytes, err = cbor.Marshal(&Result[*Signature]{
					Err: &RPCError{Message: "unknown handle"},
				})
			} else {
				respBytes, err = cbor.Marshal(&Result[*Signature]{
					Ok: &Signature{Ed25519: make([]byte, 64)},
				})
			}
		case req.Import != nil:
			s.importCalls.Add(1)
			respBytes, err = cbor.Marshal(&Result[*ImportResult]{
				Ok: &ImportResult{Handle: 1, PublicKey: PublicKey{Ed25519: make([]byte, 32)}},
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

		if b == closeAfterInit && req.Initialize != nil {
			return
		}
	}
}

func newTestClient(t *testing.T, addr string) *Client[ConfidentialSpaceCredentials] {
	t.Helper()
	dial := func(ctx context.Context) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", addr)
	}
	c := NewClient(dial, &ConfidentialSpaceCredentials{WipProviderPath: "p", EncryptionKeyPath: "k"})
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// TestSignReconnectsAfterPeerClose drives the regression: the first
// connection serves only the Initialize handshake and then closes, so
// the next Sign attempt hits a stale socket. The Client must detect
// the connection-level failure, dial a fresh socket, re-run
// Initialize, and successfully retry the Sign exactly once.
func TestSignReconnectsAfterPeerClose(t *testing.T) {
	srv := startFakeServer(t, []fakeServerBehavior{closeAfterInit, serveAll})
	client := newTestClient(t, srv.Addr())

	ctx := context.Background()
	if err := client.Connect(ctx); err != nil {
		t.Fatalf("Connect: %v", err)
	}

	sig, err := client.Sign(ctx, 42, []byte("msg"), &vault.SignOptions{Version: utils.SigningVersion1})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if sig == nil || sig.Ed25519 == nil {
		t.Fatalf("Sign returned nil signature: %+v", sig)
	}

	if got := srv.conns.Load(); got != 2 {
		t.Errorf("server saw %d connections, want 2", got)
	}
	if got := srv.signCalls.Load(); got != 1 {
		t.Errorf("server saw %d sign calls, want 1", got)
	}
}

// TestSignDoesNotRetryAfterAppError: application-level errors from
// the server pass through unchanged, with no reconnect.
func TestSignDoesNotRetryAfterAppError(t *testing.T) {
	srv := startFakeServer(t, []fakeServerBehavior{signReturnsAppError})
	client := newTestClient(t, srv.Addr())

	ctx := context.Background()
	if err := client.Connect(ctx); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if _, err := client.Sign(ctx, 42, []byte("msg"), &vault.SignOptions{Version: utils.SigningVersion1}); err == nil {
		t.Fatalf("Sign succeeded; expected RPC error")
	}
	if got := srv.conns.Load(); got != 1 {
		t.Errorf("server saw %d connections after app-level error, want 1 (no reconnect)", got)
	}
}
