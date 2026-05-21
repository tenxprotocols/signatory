package main

import (
	"context"
	"fmt"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
)

// kmsDecrypt decrypts ciphertext using the named KMS key.
// keyPath: projects/P/locations/L/keyRings/R/cryptoKeys/K
func kmsDecrypt(ctx context.Context, keyPath string, ciphertext []byte) ([]byte, error) {
	client, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("kms client: %w", err)
	}
	defer client.Close()

	resp, err := client.Decrypt(ctx, &kmspb.DecryptRequest{
		Name:       keyPath,
		Ciphertext: ciphertext,
	})
	if err != nil {
		return nil, fmt.Errorf("kms decrypt: %w", err)
	}
	return resp.Plaintext, nil
}

// kmsEncrypt encrypts plaintext using the named KMS key.
func kmsEncrypt(ctx context.Context, keyPath string, plaintext []byte) ([]byte, error) {
	client, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("kms client: %w", err)
	}
	defer client.Close()

	resp, err := client.Encrypt(ctx, &kmspb.EncryptRequest{
		Name:      keyPath,
		Plaintext: plaintext,
	})
	if err != nil {
		return nil, fmt.Errorf("kms encrypt: %w", err)
	}
	return resp.Ciphertext, nil
}

// zero overwrites b's contents. Defer this on plaintext buffers to shorten the
// in-memory window — best-effort, doesn't protect against GC copies.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
