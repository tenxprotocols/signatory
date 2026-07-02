package watermark

import (
	"context"
	"fmt"

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

	// casMaxAttempts bounds the conditional-write retry loop in
	// checkAndSet. A lost race re-reads the fresh document and re-runs
	// validation, which under contention almost always resolves to
	// ErrWatermark (the competing request recorded the same operation),
	// so the loop converges in one or two rounds.
	casMaxAttempts = 4
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

// supersededBy reports whether next advances strictly past w — the same
// monotonic (level, round) condition the DynamoDB backend enforces in its
// ConditionExpression ("lvl < :new_lvl or (lvl = :new_lvl and round < :new_round)").
func (w *GCPWatermark) supersededBy(next *GCPWatermark) bool {
	return w.Level < next.Level || (w.Level == next.Level && w.Round < next.Round)
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

	opts := metrics.IOInterceptorOptions[bool]{
		Backend:   "gcp",
		Operation: "write",
		TableName: f.colName,
		TargetFunc: func() (bool, error) {
			err := f.checkAndSet(ctx, docRef, &newWm)
			return err == nil, err
		},
	}
	_, err := metrics.IOInterceptor(&opts)
	return err
}

// checkAndSet advances the watermark with a conditional write, mirroring
// the DynamoDB backend's single conditional PutItem: validate the new
// watermark against the current document, then write guarded by a
// precondition (create-only for the first write, unchanged update time
// otherwise). Unlike a read-write transaction this holds no server-side
// locks, so a caller that gives up mid-request (e.g. a baker hitting
// remote_calls_timeout) cannot leave the document locked against other
// requests — the livelock behind the 2026-07 attestation outages, where
// canceled transactions orphaned their locks and every subsequent request
// queued behind them. A lost race surfaces as a failed precondition and
// re-runs validation against the fresh document.
func (f *GCP) checkAndSet(ctx context.Context, docRef *firestore.DocumentRef, newWm *GCPWatermark) error {
	var lastErr error
	for attempt := 0; attempt < casMaxAttempts; attempt++ {
		docSnap, err := docRef.Get(ctx)

		if err != nil {
			if status.Code(err) == codes.NotFound {
				// Document doesn't exist, safe to create. Create fails
				// with AlreadyExists if a concurrent request wins the
				// race to create it first.
				if _, err = docRef.Create(ctx, newWm); err == nil {
					return nil
				}
				if status.Code(err) == codes.AlreadyExists {
					lastErr = err
					continue
				}
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

		if !oldWm.supersededBy(newWm) {
			return ErrWatermark
		}

		_, err = docRef.Update(ctx, []firestore.Update{
			{Path: "request", Value: newWm.Request},
			{Path: "lvl", Value: newWm.Level},
			{Path: "round", Value: newWm.Round},
			{Path: "digest", Value: newWm.Digest},
		}, firestore.LastUpdateTime(docSnap.UpdateTime))
		if err == nil {
			return nil
		}
		if status.Code(err) == codes.FailedPrecondition {
			lastErr = err
			continue
		}
		metrics.RecordIOError("gcp", status.Code(err).String(), f.colName, "write")
		return fmt.Errorf("(GCPWatermark) IsSafeToSign: %w", err)
	}
	metrics.RecordIOError("gcp", "cas_exhausted", f.colName, "write")
	return fmt.Errorf("(GCPWatermark) IsSafeToSign: conditional write retries exhausted: %w", lastErr)
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
