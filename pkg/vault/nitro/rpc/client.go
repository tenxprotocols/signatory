package rpc

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"syscall"
	"time"

	"github.com/ecadlabs/signatory/pkg/vault"
	"github.com/fxamacker/cbor/v2"
	"github.com/kr/pretty"
)

// Dialer obtains a fresh net.Conn to the enclave signer.
type Dialer func(ctx context.Context) (net.Conn, error)

// Client is a connection-managing CBOR-RPC client for the enclave
// signer. RPCs are serialized; on a connection-level failure the
// Client closes, redials, re-runs Initialize, and retries once.
// Application errors and context cancellation are not retried.
type Client[C any] struct {
	Logger Logger

	dialer Dialer
	creds  *C

	mu   sync.Mutex
	conn net.Conn
}

// NewClient constructs a Client. The connection is not opened until
// Connect or the first RPC call.
func NewClient[C any](dial Dialer, creds *C) *Client[C] {
	return &Client[C]{dialer: dial, creds: creds}
}

// Connect opens the connection and runs Initialize. Must be called
// before any RPC. Subsequent reconnects happen transparently.
func (c *Client[C]) Connect(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.connectLocked(ctx)
}

func (c *Client[C]) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn == nil {
		return nil
	}
	err := c.conn.Close()
	c.conn = nil
	return err
}

type Logger interface {
	Debugf(format string, args ...interface{})
}

// isConnError reports whether err is a TCP-level failure (stale
// socket, peer close, broken pipe) rather than an application-level
// error returned by the signer.
func isConnError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, net.ErrClosed) ||
		errors.Is(err, syscall.EPIPE) || errors.Is(err, syscall.ECONNRESET) {
		return true
	}
	var opErr *net.OpError
	return errors.As(err, &opErr)
}

// InitializeConn runs the Initialize handshake on conn. The Client
// uses this internally; debug tooling calls it directly on a raw conn.
func InitializeConn[C any](ctx context.Context, conn net.Conn, cred *C, log Logger) error {
	_, err := roundTripOk[struct{}](ctx, conn, &Request[C]{Initialize: cred}, log)
	return err
}

// connectLocked closes any existing conn and establishes a fresh one
// with Initialize. The caller must hold c.mu. The Locked suffix is
// the standard Go convention for "lock-already-held" helpers.
func (c *Client[C]) connectLocked(ctx context.Context) error {
	if c.conn != nil {
		_ = c.conn.Close()
		c.conn = nil
	}
	conn, err := c.dialer(ctx)
	if err != nil {
		return err
	}
	if err := InitializeConn[C](ctx, conn, c.creds, c.Logger); err != nil {
		_ = conn.Close()
		return err
	}
	c.conn = conn
	return nil
}

// doRPC runs fn against the current conn, transparently reconnecting
// and retrying once on a connection-level failure. Connect must have
// been called first.
func doRPC[T any, C any](ctx context.Context, c *Client[C], fn func(net.Conn) (T, error)) (T, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// A previous reconnect attempt may have left c.conn nil (connectLocked
	// closes the old conn before dialing, and a dial failure returns with
	// c.conn already cleared). Re-establish here before dispatching, or
	// fn would dereference a nil net.Conn.
	if c.conn == nil {
		if rerr := c.connectLocked(ctx); rerr != nil {
			var zero T
			return zero, fmt.Errorf("rpc reconnect failed: %w", rerr)
		}
	}

	res, err := fn(c.conn)
	if err == nil || !isConnError(err) || ctx.Err() != nil {
		return res, err
	}

	if c.Logger != nil {
		c.Logger.Debugf("rpc: connection-level failure %v; reconnecting", err)
	}
	if rerr := c.connectLocked(ctx); rerr != nil {
		var zero T
		return zero, fmt.Errorf("rpc reconnect failed after %v: %w", err, rerr)
	}
	return fn(c.conn)
}

// roundTripOk performs one request/response and returns the Ok
// payload, a transport error, or a server-returned RPCError.
func roundTripOk[T any, C any](ctx context.Context, conn net.Conn, req *Request[C], log Logger) (*T, error) {
	res, err := RoundTrip[T](ctx, conn, req, log)
	if err != nil {
		return nil, err
	}
	if rerr := res.Error(); rerr != nil {
		return nil, rerr
	}
	return res.Ok, nil
}

func RoundTripRaw[T, C any](ctx context.Context, conn net.Conn, req *Request[C], log Logger) (r T, err error) {
	var debugLog func(format string, args ...interface{})
	if log != nil {
		debugLog = log.Debugf
	} else {
		debugLog = func(string, ...interface{}) {}
	}

	var res T
	reqBuf, err := cbor.Marshal(req)
	if err != nil {
		return res, err
	}
	debugLog("<<< %# v\n", pretty.Formatter(req))

	intErr := make(chan error)
	done := make(chan struct{})

	go func() {
		select {
		case <-ctx.Done():
			conn.SetDeadline(time.Unix(1, 0))
			intErr <- ctx.Err()
		case <-done:
			intErr <- nil
		}
	}()

	defer func() {
		close(done)
		if e := <-intErr; e != nil {
			err = e
		}
		conn.SetDeadline(time.Time{})
	}()

	wrBuf := make([]byte, len(reqBuf)+4)
	binary.BigEndian.PutUint32(wrBuf, uint32(len(reqBuf)))
	copy(wrBuf[4:], reqBuf)
	if _, err := conn.Write(wrBuf); err != nil {
		return res, err
	}

	var lenBuf [4]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return res, err
	}
	rBuf := make([]byte, int(binary.BigEndian.Uint32(lenBuf[:])))
	if _, err := io.ReadFull(conn, rBuf); err != nil {
		return res, err
	}
	err = cbor.Unmarshal(rBuf, &res)
	if err == nil {
		debugLog(">>> %# v\n", pretty.Formatter(&res))
	}
	return res, err
}

func RoundTrip[T, C any](ctx context.Context, conn net.Conn, req *Request[C], log Logger) (r Result[*T], err error) {
	return RoundTripRaw[Result[*T]](ctx, conn, req, log)
}

func (c *Client[C]) Import(ctx context.Context, keyData []byte) (*ImportResult, error) {
	return doRPC[*ImportResult](ctx, c, func(conn net.Conn) (*ImportResult, error) {
		return roundTripOk[ImportResult](ctx, conn, &Request[C]{Import: keyData}, c.Logger)
	})
}

func (c *Client[C]) ImportUnencrypted(ctx context.Context, priv *PrivateKey) (*GenerateAndImportResult, error) {
	return doRPC[*GenerateAndImportResult](ctx, c, func(conn net.Conn) (*GenerateAndImportResult, error) {
		return roundTripOk[GenerateAndImportResult](ctx, conn, &Request[C]{ImportUnencrypted: priv}, c.Logger)
	})
}

func (c *Client[C]) Generate(ctx context.Context, keyType KeyType) (*GenerateResult, error) {
	return doRPC[*GenerateResult](ctx, c, func(conn net.Conn) (*GenerateResult, error) {
		return roundTripOk[GenerateResult](ctx, conn, &Request[C]{Generate: &keyType}, c.Logger)
	})
}

func (c *Client[C]) GenerateAndImport(ctx context.Context, keyType KeyType) (*GenerateAndImportResult, error) {
	return doRPC[*GenerateAndImportResult](ctx, c, func(conn net.Conn) (*GenerateAndImportResult, error) {
		return roundTripOk[GenerateAndImportResult](ctx, conn, &Request[C]{GenerateAndImport: &keyType}, c.Logger)
	})
}

func (c *Client[C]) Sign(ctx context.Context, handle uint64, message []byte, opt *vault.SignOptions) (*Signature, error) {
	return doRPC[*Signature](ctx, c, func(conn net.Conn) (*Signature, error) {
		return roundTripOk[Signature](ctx, conn, &Request[C]{
			Sign: &SignRequest{Handle: handle, Message: message, Version: opt.Version.ToUint8()},
		}, c.Logger)
	})
}

func (c *Client[C]) SignWith(ctx context.Context, keyData []byte, message []byte) (*Signature, error) {
	return doRPC[*Signature](ctx, c, func(conn net.Conn) (*Signature, error) {
		return roundTripOk[Signature](ctx, conn, &Request[C]{
			SignWith: &SignWithRequest{EncryptedPrivateKey: keyData, Message: message},
		}, c.Logger)
	})
}

func (c *Client[C]) PublicKey(ctx context.Context, handle uint64) (*PublicKey, error) {
	return doRPC[*PublicKey](ctx, c, func(conn net.Conn) (*PublicKey, error) {
		return roundTripOk[PublicKey](ctx, conn, &Request[C]{PublicKey: &handle}, c.Logger)
	})
}

func (c *Client[C]) PublicKeyFrom(ctx context.Context, data []byte) (*PublicKey, error) {
	return doRPC[*PublicKey](ctx, c, func(conn net.Conn) (*PublicKey, error) {
		return roundTripOk[PublicKey](ctx, conn, &Request[C]{PublicKeyFrom: data}, c.Logger)
	})
}

func (c *Client[C]) ProvePossession(ctx context.Context, handle uint64) (*Signature, error) {
	return doRPC[*Signature](ctx, c, func(conn net.Conn) (*Signature, error) {
		return roundTripOk[Signature](ctx, conn, &Request[C]{ProvePossession: &handle}, c.Logger)
	})
}
