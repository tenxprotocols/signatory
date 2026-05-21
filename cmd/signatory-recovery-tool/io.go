package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"strings"

	"cloud.google.com/go/firestore"
)

// firestoreCollection is the default Firestore collection name used by the
// Confidential Space vault driver (matches signatory's defaultTable).
const firestoreCollection = "encrypted_keys"

// firestoreRef identifies a single Firestore document. Wire format:
//
//	PROJECT/DATABASE/COLLECTION/DOC_ID
//
// COLLECTION defaults to "encrypted_keys" if a 3-segment form is given:
//
//	PROJECT/DATABASE/DOC_ID
type firestoreRef struct {
	Project    string
	Database   string
	Collection string
	DocID      string
}

func parseFirestoreRef(s string) (*firestoreRef, error) {
	parts := strings.Split(s, "/")
	switch len(parts) {
	case 3:
		return &firestoreRef{
			Project:    parts[0],
			Database:   parts[1],
			Collection: firestoreCollection,
			DocID:      parts[2],
		}, nil
	case 4:
		return &firestoreRef{
			Project:    parts[0],
			Database:   parts[1],
			Collection: parts[2],
			DocID:      parts[3],
		}, nil
	default:
		return nil, fmt.Errorf("firestore ref must be PROJECT/DATABASE[/COLLECTION]/DOC_ID, got %q", s)
	}
}

// docItem mirrors the Firestore document shape used by signatory's
// confidentialspace driver (pkg/vault/confidentialspace/gcp_storage.go).
type docItem struct {
	PKH   string `firestore:"pkh"`
	Value []byte `firestore:"value"`
}

// readBlob resolves the blob source from the provided flags and returns the
// raw ciphertext bytes. Exactly one of (file, base64, firestoreURI) should be
// non-empty; if all are empty, stdin is used.
func readBlob(ctx context.Context, file, b64, firestoreURI string) ([]byte, error) {
	switch {
	case firestoreURI != "":
		ref, err := parseFirestoreRef(firestoreURI)
		if err != nil {
			return nil, err
		}
		client, err := firestore.NewClientWithDatabase(ctx, ref.Project, ref.Database)
		if err != nil {
			return nil, fmt.Errorf("firestore client: %w", err)
		}
		defer client.Close()
		doc, err := client.Collection(ref.Collection).Doc(ref.DocID).Get(ctx)
		if err != nil {
			return nil, fmt.Errorf("firestore get %s: %w", firestoreURI, err)
		}
		var item docItem
		if err := doc.DataTo(&item); err != nil {
			return nil, fmt.Errorf("decode firestore doc: %w", err)
		}
		if len(item.Value) == 0 {
			return nil, fmt.Errorf("firestore doc %s has empty value field", firestoreURI)
		}
		return item.Value, nil

	case b64 != "":
		return base64.StdEncoding.DecodeString(strings.TrimSpace(b64))

	case file != "" && file != "-":
		return os.ReadFile(file)

	default:
		return io.ReadAll(os.Stdin)
	}
}

// writeBlob writes the blob to the destination implied by the flags.
// Exactly one of (file, firestoreURI) should be non-empty; otherwise stdout.
// If asBase64, the raw bytes are base64-encoded before writing (file/stdout
// only; Firestore stores raw bytes regardless).
func writeBlob(ctx context.Context, file, firestoreURI, pkh string, asBase64 bool, data []byte) error {
	if firestoreURI != "" {
		ref, err := parseFirestoreRef(firestoreURI)
		if err != nil {
			return err
		}
		// Allow the doc-id segment of the URI to override pkh, or fall back to
		// the supplied pkh if the URI used a placeholder. Whichever is
		// non-empty wins; if both are set and differ, the URI wins (consistent
		// with the source being explicit).
		docID := ref.DocID
		if docID == "" {
			docID = pkh
		}
		if docID == "" {
			return fmt.Errorf("firestore write: no document id (URI or --pkh)")
		}
		client, err := firestore.NewClientWithDatabase(ctx, ref.Project, ref.Database)
		if err != nil {
			return fmt.Errorf("firestore client: %w", err)
		}
		defer client.Close()
		_, err = client.Collection(ref.Collection).Doc(docID).Set(ctx, &docItem{
			PKH:   pkh,
			Value: data,
		})
		if err != nil {
			return fmt.Errorf("firestore write %s/%s: %w", firestoreURI, docID, err)
		}
		return nil
	}

	out := data
	if asBase64 {
		out = []byte(base64.StdEncoding.EncodeToString(data) + "\n")
	}

	if file != "" && file != "-" {
		return os.WriteFile(file, out, 0o600)
	}
	_, err := os.Stdout.Write(out)
	return err
}
