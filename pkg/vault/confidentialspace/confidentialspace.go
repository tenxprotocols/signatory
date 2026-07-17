package confidentialspace

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"iter"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/ecadlabs/goblst/minpk"
	tz "github.com/ecadlabs/gotez/v2"
	"github.com/ecadlabs/gotez/v2/b58"
	"github.com/ecadlabs/gotez/v2/crypt"
	"github.com/ecadlabs/signatory/pkg/config"
	"github.com/ecadlabs/signatory/pkg/cryptoutils"
	"github.com/ecadlabs/signatory/pkg/utils"
	"github.com/ecadlabs/signatory/pkg/vault"
	"github.com/ecadlabs/signatory/pkg/vault/confidentialspace/rpc"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

const (
	DefaultPort = 2000
)

const defaultFile = "confidential_space_keys.json"

///////////////////////////////////////////////////////////////////////////////////////////

type StorageConfig struct {
	Driver string    `yaml:"driver"`
	Config yaml.Node `yaml:"config"`
}

type result[T any] interface {
	Result() iter.Seq[T]
	Err() error
}

type keyBlobStorage interface {
	GetKeys(ctx context.Context) (result[*encryptedKey], error)
	ImportKey(ctx context.Context, encryptedKey *encryptedKey) error
}

///////////////////////////////////////////////////////////////////////////////////////////

type encryptedKey struct {
	PublicKeyHash       tz.PublicKeyHash `json:"public_key_hash"`
	EncryptedPrivateKey []byte           `json:"encrypted_private_key"`
}

func (e *encryptedKey) UnmarshalJSON(data []byte) error {
	type Alias encryptedKey
	aux := &struct {
		PublicKeyHash string `json:"public_key_hash"`
		*Alias
	}{
		Alias: (*Alias)(e),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	pkh, err := b58.ParsePublicKeyHash([]byte(aux.PublicKeyHash))
	if err != nil {
		return err
	}
	e.PublicKeyHash = pkh
	return nil
}

///////////////////////////////////////////////////////////////////////////////////////////

type Config struct {
	ConfidentialSpaceHost string         `yaml:"host"`
	ConfidentialSpacePort string         `yaml:"port"`
	WipProviderPath       string         `yaml:"wip_provider_path"`
	EncryptionKeyPath     string         `yaml:"encryption_key_path"`
	Storage               *StorageConfig `yaml:"storage"`
}

func resolve[T comparable](value T, ev string) T {
	var zero T
	if value == zero {
		if env := os.Getenv(ev); env != "" {
			var tmp T
			if _, err := fmt.Sscanf(env, "%v", &tmp); err == nil {
				return tmp
			}
		}
	}
	return value
}

func populateConfig(c *Config) *Config {
	if c == nil {
		var zero Config
		c = &zero
	}
	return &Config{
		ConfidentialSpaceHost: resolve(c.ConfidentialSpaceHost, "CONFIDENTIAL_SPACE_HOST"),
		ConfidentialSpacePort: resolve(c.ConfidentialSpacePort, "CONFIDENTIAL_SPACE_PORT"),
		WipProviderPath:       resolve(c.WipProviderPath, "GCP_WIP_PROVIDER_PATH"),
		EncryptionKeyPath:     resolve(c.EncryptionKeyPath, "GCP_KMS_ENCRYPTION_KEY_PATH"),
		Storage:               c.Storage,
	}
}

///////////////////////////////////////////////////////////////////////////////////////////

type ConfidentialSpaceVault[C any] struct {
	client  *rpc.Client[C]
	storage keyBlobStorage
	keys    []*confidentialKey
	mtx     sync.Mutex
}

func (v *ConfidentialSpaceVault[C]) List(ctx context.Context) vault.KeyIterator {
	v.mtx.Lock()
	defer v.mtx.Unlock()

	snap := v.keys
	i := 0
	return vault.IteratorFunc(func() (key vault.KeyReference, err error) {
		if i >= len(snap) {
			return nil, vault.ErrDone
		}
		k := &confidentialKeyRef[C]{
			confidentialKey: snap[i],
			v:               v,
		}
		i++
		return k, nil
	})
}

func (v *ConfidentialSpaceVault[C]) Close(ctx context.Context) (err error) {
	err = v.client.Close()
	return err
}

func (v *ConfidentialSpaceVault[C]) Name() string { return "ConfidentialSpace" }

func (v *ConfidentialSpaceVault[C]) Import(ctx context.Context, pk crypt.PrivateKey, opt utils.Options) (vault.KeyReference, error) {
	rpcPk, err := rpc.NewPrivateKey(pk)
	if err != nil {
		return nil, fmt.Errorf("(ConfidentialSpace): %w", err)
	}

	v.mtx.Lock()
	defer v.mtx.Unlock()

	res, err := v.client.ImportUnencrypted(ctx, rpcPk)
	if err != nil {
		return nil, fmt.Errorf("(ConfidentialSpace): %w", err)
	}
	p, err := res.PublicKey.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("(ConfidentialSpace): %w", err)
	}
	key := &confidentialKey{
		pub:          p,
		handle:       res.Handle,
		encryptedKey: res.EncryptedPrivateKey,
	}
	v.keys = append(v.keys, key)

	if err := v.storage.ImportKey(ctx, &encryptedKey{
		PublicKeyHash:       p.Hash(),
		EncryptedPrivateKey: res.EncryptedPrivateKey,
	}); err != nil {
		return nil, fmt.Errorf("(ConfidentialSpace): %w", err)
	}

	return &confidentialKeyRef[C]{
		confidentialKey: key,
		v:               v,
	}, nil
}

func (v *ConfidentialSpaceVault[C]) Generate(ctx context.Context, keyType *cryptoutils.KeyType, n int) (vault.KeyIterator, error) {
	var kt rpc.KeyType
	switch keyType {
	case cryptoutils.KeyEd25519:
		kt = rpc.KeyEd25519
	case cryptoutils.KeySecp256k1:
		kt = rpc.KeySecp256k1
	case cryptoutils.KeyP256:
		kt = rpc.KeyNISTP256
	case cryptoutils.KeyBLS12_381:
		kt = rpc.KeyBLS
	default:
		return nil, fmt.Errorf("(ConfidentialSpace): unsupported key type %v", keyType)
	}

	v.mtx.Lock()
	defer v.mtx.Unlock()

	var imported []*confidentialKey
	for i := 0; i < n; i++ {
		res, err := v.client.GenerateAndImport(ctx, kt)
		if err != nil {
			return nil, fmt.Errorf("(ConfidentialSpace): %w", err)
		}
		p, err := res.PublicKey.PublicKey()
		if err != nil {
			return nil, fmt.Errorf("(ConfidentialSpace): %w", err)
		}
		key := &confidentialKey{
			pub:          p,
			handle:       res.Handle,
			encryptedKey: res.EncryptedPrivateKey,
		}
		v.keys = append(v.keys, key)
		if err := v.storage.ImportKey(ctx, &encryptedKey{
			PublicKeyHash:       p.Hash(),
			EncryptedPrivateKey: res.EncryptedPrivateKey,
		}); err != nil {
			return nil, fmt.Errorf("(ConfidentialSpace): %w", err)
		}
		imported = append(imported, key)
	}

	i := 0
	return vault.IteratorFunc(func() (key vault.KeyReference, err error) {
		if i >= len(imported) {
			return nil, vault.ErrDone
		}
		k := &confidentialKeyRef[C]{
			confidentialKey: imported[i],
			v:               v,
		}
		i++
		return k, nil
	}), nil
}

///////////////////////////////////////////////////////////////////////////////////////////

type confidentialKey struct {
	pub    crypt.PublicKey
	handle uint64
	// encryptedKey is the KMS-wrapped blob the tee-signer needs to
	// recover this key. Kept alongside the handle so re-Import after a
	// tee-signer restart doesn't have to round-trip to Firestore on the
	// signing hot path. See reimportLocked.
	encryptedKey []byte
}

// isStaleHandleError reports whether err signals that the tee-signer no
// longer recognizes the handle, which happens after a tee-signer VM
// restart wipes its in-memory handle table. The tee-signer sends a
// nested RPCError of the form {message:"signer error", source:{message:
// "invalid handle"}}; both levels are checked in case the wrapping
// changes upstream.
func isStaleHandleError(err error) bool {
	var rerr *rpc.RPCError
	if !errors.As(err, &rerr) {
		return false
	}
	for e := rerr; e != nil; e = e.Source {
		if strings.EqualFold(strings.TrimSpace(e.Message), "invalid handle") {
			return true
		}
	}
	return false
}

// reimportAllLocked re-Imports every key's encrypted blob into the
// tee-signer and updates the handles in place. Caller must hold v.mtx
// so concurrent Sign or ProvePossession calls can't race against the
// handle updates.
//
// This is the recovery path for the case where the tee-signer has lost
// or rebuilt its in-memory handle table (restart, session reset). It
// deliberately re-binds ALL keys, not just the one that observed the
// failure: a table reset invalidates every cached handle at once, and a
// sibling key's stale handle can silently collide with a freshly
// allocated slot and sign with the wrong key (2026-07-17 mainnet
// incident). Each returned public key is checked against the cached one
// before the handle is adopted — a mismatch means the blob resolves to
// foreign key material and must never be bound.
func (v *ConfidentialSpaceVault[C]) reimportAllLocked(ctx context.Context, reason string) error {
	log.WithField("reason", reason).Warn(
		"tee-signer handle table presumed lost; re-importing all keys")
	for _, k := range v.keys {
		if k.encryptedKey == nil {
			return fmt.Errorf("key %v has no cached encrypted blob; cannot re-import", k.pub.Hash())
		}
		res, err := v.client.Import(ctx, k.encryptedKey)
		if err != nil {
			return err
		}
		p, err := res.PublicKey.PublicKey()
		if err != nil {
			return err
		}
		if !p.Equal(k.pub) {
			return fmt.Errorf("re-imported blob for %v resolved to foreign public key %v; refusing to bind",
				k.pub.Hash(), p.Hash())
		}
		k.handle = res.Handle
	}
	return nil
}

// verifySignature checks that sig is a valid signature by pub over
// message, mirroring the signing-version semantics the signer applies
// (BLS keys sign with the augmented ciphersuite under version 1 and the
// default ciphersuite otherwise; other key types are version-independent).
func verifySignature(pub crypt.PublicKey, sig crypt.Signature, message []byte, opt *vault.SignOptions) bool {
	ver := utils.SigningVersionLatest
	if opt != nil {
		ver = opt.Version
	}
	if bpub, ok := pub.(*crypt.BLSPublicKey); ok && ver == utils.SigningVersion1 {
		return bpub.VerifySignatureAugmented(sig, message)
	}
	return pub.VerifySignature(sig, message)
}

type confidentialKeyRef[C any] struct {
	*confidentialKey
	v *ConfidentialSpaceVault[C]
}

func (r *confidentialKeyRef[C]) PublicKey() crypt.PublicKey { return r.pub }
func (r *confidentialKeyRef[C]) Vault() vault.Vault         { return r.v }

// callVerified runs one enclave signing RPC and returns its result only
// if it passes verify. It recovers at most once — from a stale handle
// or from a verification failure — by re-binding all handles via
// reimportAllLocked and re-issuing the call; call must therefore read
// the key's current handle on each invocation. Caller must hold v.mtx.
func (r *confidentialKeyRef[C]) callVerified(ctx context.Context, what string, call func() (*rpc.Signature, error), verify func(crypt.Signature) bool) (crypt.Signature, error) {
	recovered := false
	sig, err := call()
	if isStaleHandleError(err) {
		if rerr := r.v.reimportAllLocked(ctx, "stale handle on "+what); rerr != nil {
			return nil, fmt.Errorf("(ConfidentialSpace): reimport after stale handle: %w", rerr)
		}
		recovered = true
		sig, err = call()
	}
	if err != nil {
		return nil, fmt.Errorf("(ConfidentialSpace): %w", err)
	}
	res, err := sig.Signature()
	if err != nil {
		return nil, fmt.Errorf("(ConfidentialSpace): %w", err)
	}

	// The enclave is not trusted to have signed with the right key: a
	// rebuilt handle table silently binds cached handles to foreign key
	// material. Never return a result that does not verify.
	if !verify(res) {
		log.WithField("pkh", r.pub.Hash()).WithField("handle", r.handle).Errorf(
			"enclave returned a %s that does not verify; re-binding all handles", what)
		if !recovered {
			if rerr := r.v.reimportAllLocked(ctx, what+" failed verification"); rerr != nil {
				return nil, fmt.Errorf("(ConfidentialSpace): reimport after failed verification: %w", rerr)
			}
			if sig, err = call(); err != nil {
				return nil, fmt.Errorf("(ConfidentialSpace): %w", err)
			}
			if res, err = sig.Signature(); err != nil {
				return nil, fmt.Errorf("(ConfidentialSpace): %w", err)
			}
			if verify(res) {
				return res, nil
			}
		}
		return nil, fmt.Errorf("(ConfidentialSpace): %s by %v failed verification after handle re-bind", what, r.pub.Hash())
	}
	return res, nil
}

func (r *confidentialKeyRef[C]) Sign(ctx context.Context, message []byte, opt *vault.SignOptions) (crypt.Signature, error) {
	r.v.mtx.Lock()
	defer r.v.mtx.Unlock()

	return r.callVerified(ctx, "signature",
		func() (*rpc.Signature, error) { return r.v.client.Sign(ctx, r.handle, message, opt) },
		func(sig crypt.Signature) bool { return verifySignature(r.pub, sig, message, opt) })
}

// verifyPossession checks a BLS proof of possession against pub. Proofs
// for non-BLS keys have no defined verification here and are accepted
// as-is.
func verifyPossession(pub crypt.PublicKey, sig crypt.Signature) bool {
	bpub, ok := pub.(*crypt.BLSPublicKey)
	if !ok {
		return true
	}
	bsig, ok := sig.(*crypt.BLSSignature)
	if !ok {
		return false
	}
	return minpk.VerifyProof((*minpk.PublicKey)(bpub), (*minpk.Signature)(bsig)) == nil
}

func (r *confidentialKeyRef[C]) ProvePossession(ctx context.Context) (crypt.Signature, error) {
	r.v.mtx.Lock()
	defer r.v.mtx.Unlock()

	return r.callVerified(ctx, "proof of possession",
		func() (*rpc.Signature, error) { return r.v.client.ProvePossession(ctx, r.handle) },
		func(sig crypt.Signature) bool { return verifyPossession(r.pub, sig) })
}

///////////////////////////////////////////////////////////////////////////////////////////

func New(ctx context.Context, config *Config, global config.GlobalContext) (*ConfidentialSpaceVault[rpc.ConfidentialSpaceCredentials], error) {
	var sc *StorageConfig
	if config != nil {
		sc = config.Storage
	}
	storage, err := newStorage(ctx, sc, global)
	if err != nil {
		return nil, fmt.Errorf("(ConfidentialSpace): %w", err)
	}
	return newWithStorage(ctx, config, storage)
}

func newStorage(ctx context.Context, conf *StorageConfig, global config.GlobalContext) (keyBlobStorage, error) {
	if conf != nil {
		switch conf.Driver {
		case "file":
			var path string
			if conf.Config.IsZero() {
				path = filepath.Join(global.GetBaseDir(), defaultFile)
			} else if err := conf.Config.Decode(&path); err == nil {
				path = os.ExpandEnv(path)
			} else {
				return nil, err
			}
			return newFileStorage(path)
		case "gcp", "firestore":
			var cfg gcpStorageConfig
			if !conf.Config.IsZero() {
				if err := conf.Config.Decode(&cfg); err != nil {
					return nil, err
				}
			}
			return newGCPStorage(ctx, &cfg)
		default:
			return nil, fmt.Errorf("(ConfidentialSpace): unknown key storage %s", conf.Driver)
		}
	} else {
		path := filepath.Join(global.GetBaseDir(), defaultFile)
		return newFileStorage(path)
	}
}

func newWithStorage(ctx context.Context, config *Config, storage keyBlobStorage) (*ConfidentialSpaceVault[rpc.ConfidentialSpaceCredentials], error) {
	conf := populateConfig(config)

	if conf.ConfidentialSpaceHost == "" {
		return nil, errors.New("(ConfidentialSpace): missing confidential space host")
	}
	if conf.EncryptionKeyPath == "" {
		return nil, errors.New("(ConfidentialSpace): missing encryption key path")
	}

	rpcCred := rpc.ConfidentialSpaceCredentials{
		WipProviderPath:   conf.WipProviderPath,
		EncryptionKeyPath: conf.EncryptionKeyPath,
	}
	if !rpcCred.IsValid() {
		return nil, errors.New("(ConfidentialSpace): invalid credentials")
	}

	addr := net.JoinHostPort(conf.ConfidentialSpaceHost, conf.ConfidentialSpacePort)
	log.Infof("(ConfidentialSpace): connecting to the enclave signer on %v...", addr)

	dial := func(ctx context.Context) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", addr)
	}
	return newWithClient(ctx, rpc.NewClient(dial, &rpcCred), storage)
}

func newWithClient[C any](ctx context.Context, client *rpc.Client[C], storage keyBlobStorage) (*ConfidentialSpaceVault[C], error) {
	client.Logger = log.StandardLogger()

	// Open the initial connection eagerly so vault construction fails
	// fast if the enclave is unreachable. Subsequent reconnects happen
	// transparently inside the rpc.Client.
	if err := client.Connect(ctx); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("(ConfidentialSpace): %w", err)
	}

	r, err := storage.GetKeys(ctx)
	if err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("(ConfidentialSpace): %w", err)
	}

	var keys []*confidentialKey
	for k := range r.Result() {
		log.WithField("pkh", k.PublicKeyHash).Debug("Importing encrypted key")
		res, err := client.Import(ctx, k.EncryptedPrivateKey)
		if err != nil {
			_ = client.Close()
			return nil, fmt.Errorf("(ConfidentialSpace): %w", err)
		}
		p, err := res.PublicKey.PublicKey()
		if err != nil {
			_ = client.Close()
			return nil, fmt.Errorf("(ConfidentialSpace): %w", err)
		}
		if string(p.Hash().ToBase58()) != string(k.PublicKeyHash.ToBase58()) {
			_ = client.Close()
			return nil, fmt.Errorf("(ConfidentialSpace): blob stored for %v resolved to foreign public key %v; refusing to bind",
				k.PublicKeyHash, p.Hash())
		}
		keys = append(keys, &confidentialKey{
			pub:          p,
			handle:       res.Handle,
			encryptedKey: k.EncryptedPrivateKey,
		})
	}
	if err := r.Err(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("(ConfidentialSpace): %w", err)
	}

	return &ConfidentialSpaceVault[C]{
		client:  client,
		storage: storage,
		keys:    keys,
	}, nil
}

///////////////////////////////////////////////////////////////////////////////////////////

func init() {
	vault.RegisterVault("confidentialspace", func(ctx context.Context, node *yaml.Node, global config.GlobalContext) (vault.Vault, error) {
		var conf *Config
		if node != nil && !node.IsZero() {
			conf = &Config{}
			if err := node.Decode(conf); err != nil {
				return nil, err
			}
		}
		return New(ctx, conf, global)
	})
}

///////////////////////////////////////////////////////////////////////////////////////////

var (
	_ vault.Importer  = (*ConfidentialSpaceVault[rpc.ConfidentialSpaceCredentials])(nil)
	_ vault.Generator = (*ConfidentialSpaceVault[rpc.ConfidentialSpaceCredentials])(nil)
)
