package watermark

import (
	"context"
	"fmt"
	"time"

	tz "github.com/ecadlabs/gotez/v2"
	"github.com/ecadlabs/gotez/v2/crypt"
	"github.com/ecadlabs/gotez/v2/protocol/core" // Import config directly
	"github.com/ecadlabs/signatory/pkg/config"
	"github.com/ecadlabs/signatory/pkg/metrics"
	"github.com/ecadlabs/signatory/pkg/signatory/request"
	"github.com/ecadlabs/signatory/pkg/utils/gcp"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gopkg.in/yaml.v3"

	"cloud.google.com/go/firestore"
)

const (
	defaultCollection = "watermark"

	// transactionTimeout is a safety valve against an indefinitely stuck
	// Firestore RPC, nothing more — correctness must never depend on its
	// value. It is deliberately generous: Firestore's own server-side
	// transaction limits expire a transaction long before this fires, so
	// the transaction always gets to commit or roll back on its own terms.
	transactionTimeout = 60 * time.Second
)

type GCPConfig struct {
	gcp.Config `yaml:",inline"`
	Project    string `yaml:"project" validate:"required"`
	Database   string `yaml:"database" validate:"required"`
	Collection string `yaml:"collection"`
}

func (c *GCPConfig) collection() string {
	if c.Collection != "" {
		return c.Collection
	}
	return defaultCollection
}

type GCP struct {
	client  *firestore.Client
	col     *firestore.CollectionRef
	colName string
}

func NewGCPWatermark(ctx context.Context, config *GCPConfig) (*GCP, error) {
	var client *firestore.Client
	var err error

	opts, err := gcp.NewGCPOption(ctx, &config.Config)
	if err != nil {
		return nil, fmt.Errorf("(GCPWatermark) NewGCPWatermark: %w", err)
	}

	if config.Database == "" {
		client, err = firestore.NewClient(ctx, config.Project, opts...)
	} else {
		client, err = firestore.NewClientWithDatabase(ctx, config.Project, config.Database, opts...)
	}
	if err != nil {
		return nil, fmt.Errorf("(GCPWatermark) NewGCPWatermark: %w", err)
	}

	colName := config.collection()
	col := client.Collection(colName)

	inst := GCP{
		client:  client,
		col:     col,
		colName: colName,
	}

	return &inst, nil
}

type GCPWatermark struct {
	Request string               `firestore:"request"`
	Level   int32                `firestore:"lvl"`
	Round   int32                `firestore:"round"`
	Digest  *tz.BlockPayloadHash `firestore:"digest"`
}

func (f *GCP) IsSafeToSign(ctx context.Context, pkh crypt.PublicKeyHash, req core.SignRequest, digest *crypt.Digest) error {
	m, ok := req.(request.WithWatermark)
	if !ok {
		// watermark is not required
		return nil
	}

	docRef := f.col.Doc(m.GetChainID().String()).Collection(req.SignRequestKind()).Doc(pkh.String())

	wm := request.NewWatermark(m, digest)

	newWm := GCPWatermark{
		Request: req.SignRequestKind(),
		Level:   wm.Level,
		Round:   wm.Round,
		Digest:  wm.Hash.UnwrapPtr(),
	}

	// Detach from the caller's cancellation (context values are preserved):
	// once the transaction starts it must commit or roll back cleanly no
	// matter what the client does. Baker clients cancel sign requests
	// aggressively (octez remote_calls_timeout); when that cancellation
	// propagated into RunTransaction the SDK could neither commit nor roll
	// back, orphaning the server-side transaction's document locks. With
	// multiple bakers racing on the same key, each new request then queued
	// behind the orphans, timed out, and orphaned its own transaction in
	// turn — a self-sustaining livelock that blocked every mainnet
	// attestation for ~2h on 2026-07-01.
	txCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), transactionTimeout)
	defer cancel()

	opts := metrics.IOInterceptorOptions[bool]{
		Backend:   "gcp",
		Operation: "write",
		TableName: f.colName,
		TargetFunc: func() (bool, error) {
			err := f.client.RunTransaction(txCtx, func(ctx context.Context, tx *firestore.Transaction) error {
				docSnap, err := tx.Get(docRef) // Read document

				if err != nil {
					if status.Code(err) == codes.NotFound {
						// Document doesn't exist, safe to create
						tx.Set(docRef, newWm)
						return nil
					}
					metrics.RecordIOError("gcp", status.Code(err).String(), f.colName, "write")
					return fmt.Errorf("(GCPWatermark) IsSafeToSign: %w", err)
				}

				// Document exists, check watermark
				var oldWm GCPWatermark
				if err := docSnap.DataTo(&oldWm); err != nil {
					metrics.RecordIOError("gcp", "decode_error", f.colName, "write")
					return fmt.Errorf("(GCPWatermark) IsSafeToSign: %w", err)
				}

				if oldWm.Level >= newWm.Level && (oldWm.Level != newWm.Level || oldWm.Round >= newWm.Round) {
					return ErrWatermark
				}

				tx.Set(docRef, newWm)
				return nil
			})
			return err == nil, err
		},
	}
	_, err := metrics.IOInterceptor(&opts)
	return err
}

func init() {
	RegisterWatermark("gcp", func(ctx context.Context, node *yaml.Node, global config.GlobalContext) (watermarkImpl, error) {
		var config GCPConfig
		if node != nil {
			if err := node.Decode(&config); err != nil {
				return nil, err
			}
		}
		return NewGCPWatermark(ctx, &config)
	})
}
