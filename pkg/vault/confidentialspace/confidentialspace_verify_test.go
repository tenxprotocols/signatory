package confidentialspace

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"io"
	"iter"
	"net"
	"sync"
	"testing"

	"github.com/ecadlabs/gotez/v2/crypt"
	"github.com/ecadlabs/signatory/pkg/utils"
	"github.com/ecadlabs/signatory/pkg/vault"
	"github.com/ecadlabs/signatory/pkg/vault/confidentialspace/rpc"
	"github.com/fxamacker/cbor/v2"
)

// tableFakeServer models the tee-signer's real handle semantics: an
// in-memory table of handle -> private key with sequential allocation
// starting at 0, where Import binds the key identified by the blob to
// the next free handle and Sign uses whatever key currently lives at
// the requested handle. Unknown handles produce the "invalid handle"
// error chain; known-but-rebound handles sign silently with the wrong
// key — the production failure mode.
type tableFakeServer struct {
	t  *testing.T
	ln net.Listener

	mtx      sync.Mutex
	registry map[string]ed25519.PrivateKey // blob -> key it decrypts to
	table    map[uint64]ed25519.PrivateKey // handle -> key
	next     uint64
	imports  int
}

func startTableFakeServer(t *testing.T) *tableFakeServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &tableFakeServer{
		t:        t,
		ln:       ln,
		registry: make(map[string]ed25519.PrivateKey),
		table:    make(map[uint64]ed25519.PrivateKey),
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serveConn(conn)
		}
	}()
	return s
}

func (s *tableFakeServer) Addr() string { return s.ln.Addr().String() }

// Register associates blob with a key, as if the blob were that key's
// KMS-encrypted form. Returns the key's crypt public key.
func (s *tableFakeServer) Register(blob []byte, priv ed25519.PrivateKey) crypt.PublicKey {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	s.registry[string(blob)] = priv
	return crypt.Ed25519PublicKey(priv.Public().(ed25519.PublicKey))
}

// Bind places a key at the next free handle without an Import call,
// standing in for imports done by other signatory replicas sharing the
// enclave. Returns the allocated handle.
func (s *tableFakeServer) Bind(priv ed25519.PrivateKey) uint64 {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	h := s.next
	s.next++
	s.table[h] = priv
	return h
}

// Reset wipes the handle table and restarts allocation from zero, as a
// tee-signer restart does.
func (s *tableFakeServer) Reset() {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	s.table = make(map[uint64]ed25519.PrivateKey)
	s.next = 0
}

func (s *tableFakeServer) ImportCalls() int {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	return s.imports
}

func (s *tableFakeServer) serveConn(conn net.Conn) {
	defer conn.Close()
	for {
		var lenBuf [4]byte
		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			return
		}
		body := make([]byte, binary.BigEndian.Uint32(lenBuf[:]))
		if _, err := io.ReadFull(conn, body); err != nil {
			return
		}
		var req rpc.Request[rpc.ConfidentialSpaceCredentials]
		if err := cbor.Unmarshal(body, &req); err != nil {
			s.t.Errorf("server: bad cbor: %v", err)
			return
		}
		respBytes, err := s.respond(&req)
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

func (s *tableFakeServer) respond(req *rpc.Request[rpc.ConfidentialSpaceCredentials]) ([]byte, error) {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	switch {
	case req.Initialize != nil:
		return cbor.Marshal(&rpc.Result[*struct{}]{Ok: &struct{}{}})
	case req.Import != nil:
		s.imports++
		priv, ok := s.registry[string(req.Import)]
		if !ok {
			return cbor.Marshal(&rpc.Result[*rpc.ImportResult]{
				Err: &rpc.RPCError{Message: "signer error", Source: &rpc.RPCError{Message: "decryption failed"}},
			})
		}
		h := s.next
		s.next++
		s.table[h] = priv
		return cbor.Marshal(&rpc.Result[*rpc.ImportResult]{
			Ok: &rpc.ImportResult{
				Handle:    h,
				PublicKey: rpc.PublicKey{Ed25519: priv.Public().(ed25519.PublicKey)},
			},
		})
	case req.Sign != nil:
		priv, ok := s.table[req.Sign.Handle]
		if !ok {
			return cbor.Marshal(&rpc.Result[*rpc.Signature]{
				Err: &rpc.RPCError{Message: "signer error", Source: &rpc.RPCError{Message: "invalid handle"}},
			})
		}
		digest := crypt.DigestFunc(req.Sign.Message)
		return cbor.Marshal(&rpc.Result[*rpc.Signature]{
			Ok: &rpc.Signature{Ed25519: ed25519.Sign(priv, digest[:])},
		})
	default:
		return cbor.Marshal(&rpc.Result[*struct{}]{
			Err: &rpc.RPCError{Message: "unexpected request"},
		})
	}
}

func genKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	return priv
}

func newTestVault(t *testing.T, srv *tableFakeServer) *ConfidentialSpaceVault[rpc.ConfidentialSpaceCredentials] {
	t.Helper()
	dial := func(ctx context.Context) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", srv.Addr())
	}
	cli := rpc.NewClient(dial, &rpc.ConfidentialSpaceCredentials{WipProviderPath: "p", EncryptionKeyPath: "k"})
	t.Cleanup(func() { _ = cli.Close() })
	if err := cli.Connect(context.Background()); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	return &ConfidentialSpaceVault[rpc.ConfidentialSpaceCredentials]{client: cli}
}

func addKey(v *ConfidentialSpaceVault[rpc.ConfidentialSpaceCredentials], pub crypt.PublicKey, handle uint64, blob []byte) (*confidentialKey, *confidentialKeyRef[rpc.ConfidentialSpaceCredentials]) {
	k := &confidentialKey{pub: pub, handle: handle, encryptedKey: blob}
	v.keys = append(v.keys, k)
	return k, &confidentialKeyRef[rpc.ConfidentialSpaceCredentials]{confidentialKey: k, v: v}
}

var signV2 = &vault.SignOptions{Version: utils.SigningVersion2}

// TestSignRejectsCrossedHandleSignature reproduces the 2026-07-17
// incident: the enclave's handle table was rebuilt and the cached
// handle now points at a different key. The enclave signs without
// error, but with the wrong key. Sign must never hand that signature
// back — it must recover (re-import and retry) and return a signature
// that verifies under the key's public key.
func TestSignRejectsCrossedHandleSignature(t *testing.T) {
	srv := startTableFakeServer(t)
	v := newTestVault(t, srv)

	keyB := genKey(t)
	blobB := []byte("blob-B")
	pubB := srv.Register(blobB, keyB)

	// Slot 0 belongs to a foreign key (another replica's re-import);
	// our cached handle for B still says 0.
	srv.Bind(genKey(t))
	_, refB := addKey(v, pubB, 0, blobB)

	msg := []byte("consensus operation bytes")
	sig, err := refB.Sign(context.Background(), msg, signV2)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !pubB.VerifySignature(sig, msg) {
		t.Fatal("Sign returned a signature that does not verify under the key's public key")
	}
}

// TestSignErrorsWhenRecoveryYieldsForeignKey: if re-import resolves the
// blob to a key whose public key does not match the cached one (wrong
// blob in storage, enclave misbehavior), Sign must fail loudly rather
// than bind the handle and sign with foreign material.
func TestSignErrorsWhenRecoveryYieldsForeignKey(t *testing.T) {
	srv := startTableFakeServer(t)
	v := newTestVault(t, srv)

	keyB := genKey(t)
	blobB := []byte("blob-B")
	srv.Register(blobB, keyB)
	pubB := crypt.Ed25519PublicKey(keyB.Public().(ed25519.PublicKey))

	// The blob re-imports to a DIFFERENT key than the one cached.
	foreign := genKey(t)
	srv.registry[string(blobB)] = foreign

	// Crossed handle to force recovery.
	srv.Bind(genKey(t))
	key, refB := addKey(v, pubB, 0, blobB)
	oldHandle := key.handle

	msg := []byte("consensus operation bytes")
	sig, err := refB.Sign(context.Background(), msg, signV2)
	if err == nil {
		if !pubB.VerifySignature(sig, msg) {
			t.Fatal("Sign returned a non-verifying signature instead of an error")
		}
		t.Fatal("Sign succeeded but recovery should have failed on public key mismatch")
	}
	if key.handle != oldHandle {
		t.Errorf("handle was rebound to a foreign key: %d -> %d", oldHandle, key.handle)
	}
}

// TestStaleHandleRecoveryRebindsAllKeys: an "invalid handle" error is
// evidence the enclave lost its handle table for every key, not just
// the one being signed. Recovery must re-resolve all sibling keys;
// otherwise a sibling's stale handle can silently collide with a
// freshly allocated slot and sign with the wrong key.
func TestStaleHandleRecoveryRebindsAllKeys(t *testing.T) {
	srv := startTableFakeServer(t)
	v := newTestVault(t, srv)

	keyA, keyB := genKey(t), genKey(t)
	blobA, blobB := []byte("blob-A"), []byte("blob-B")
	pubA := srv.Register(blobA, keyA)
	pubB := srv.Register(blobB, keyB)

	// Pre-incident state: A at handle 5, B at handle 1.
	_, refA := addKey(v, pubA, 5, blobA)
	kB, refB := addKey(v, pubB, 1, blobB)

	// Enclave restarts; other replicas' imports fill slots 0 and 1.
	srv.Reset()
	srv.Bind(genKey(t))
	srv.Bind(genKey(t)) // occupies B's stale handle 1

	msg := []byte("consensus operation bytes")

	// A's handle 5 is unknown -> "invalid handle" -> recovery.
	sigA, err := refA.Sign(context.Background(), msg, signV2)
	if err != nil {
		t.Fatalf("Sign A: %v", err)
	}
	if !pubA.VerifySignature(sigA, msg) {
		t.Fatal("Sign A returned a non-verifying signature")
	}

	// B must have been re-bound by A's recovery; its old handle 1 now
	// holds a foreign key and must not be used.
	if kB.handle == 1 {
		t.Fatal("sibling key B was not re-bound during recovery")
	}
	sigB, err := refB.Sign(context.Background(), msg, signV2)
	if err != nil {
		t.Fatalf("Sign B: %v", err)
	}
	if !pubB.VerifySignature(sigB, msg) {
		t.Fatal("Sign B returned a non-verifying signature (stale sibling handle was used)")
	}
}

// TestStartupRejectsForeignPublicKey: at vault construction, the public
// key the enclave reports for an imported blob must match the public
// key hash recorded in storage.
func TestStartupRejectsForeignPublicKey(t *testing.T) {
	srv := startTableFakeServer(t)

	keyA := genKey(t)
	blobA := []byte("blob-A")
	pubA := srv.Register(blobA, keyA)

	// Storage claims the blob belongs to a different key.
	foreign := genKey(t)
	foreignPub := crypt.Ed25519PublicKey(foreign.Public().(ed25519.PublicKey))
	storage := &fakeStorage{keys: []*encryptedKey{{
		PublicKeyHash:       foreignPub.Hash(),
		EncryptedPrivateKey: blobA,
	}}}

	dial := func(ctx context.Context) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", srv.Addr())
	}
	cli := rpc.NewClient(dial, &rpc.ConfidentialSpaceCredentials{WipProviderPath: "p", EncryptionKeyPath: "k"})
	_, err := newWithClient(context.Background(), cli, storage)
	if err == nil {
		t.Fatalf("newWithClient accepted a blob whose enclave public key %v does not match storage's %v",
			pubA.Hash(), foreignPub.Hash())
	}
}

type fakeStorage struct {
	keys []*encryptedKey
}

type sliceResult[T any] struct{ items []T }

func (s sliceResult[T]) Result() iter.Seq[T] {
	return func(yield func(T) bool) {
		for _, x := range s.items {
			if !yield(x) {
				return
			}
		}
	}
}
func (s sliceResult[T]) Err() error { return nil }

func (f *fakeStorage) GetKeys(ctx context.Context) (result[*encryptedKey], error) {
	return sliceResult[*encryptedKey]{items: f.keys}, nil
}
func (f *fakeStorage) ImportKey(ctx context.Context, k *encryptedKey) error {
	f.keys = append(f.keys, k)
	return nil
}
