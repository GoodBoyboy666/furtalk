package cryptox

import (
	"bytes"
	"errors"
	"testing"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, derivedKeyLength)
	plaintext := []byte("secret provider configuration")

	envelope, err := Encrypt(key, 7, plaintext)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}
	if len(envelope) != envelopeKeyVersionLength+gcmNonceLength+len(plaintext)+gcmOverheadLength {
		t.Fatalf("envelope length = %d, want %d", len(envelope), envelopeKeyVersionLength+gcmNonceLength+len(plaintext)+gcmOverheadLength)
	}
	if envelope[0] != 7 {
		t.Fatalf("envelope key version = %d, want 7", envelope[0])
	}

	got, err := Decrypt(key, 7, envelope)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("decrypted plaintext = %q, want %q", got, plaintext)
	}
}

func TestDecryptRejectsWrongVersionAndTampering(t *testing.T) {
	key := bytes.Repeat([]byte{0x24}, derivedKeyLength)
	envelope, err := Encrypt(key, 1, []byte("payload"))
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}
	if _, err := Decrypt(key, 2, envelope); err != ErrBadEnvelope {
		t.Fatalf("wrong version error = %v, want ErrBadEnvelope", err)
	}

	tampered := append([]byte(nil), envelope...)
	tampered[len(tampered)-1] ^= 1
	if _, err := Decrypt(key, 1, tampered); err != ErrBadEnvelope {
		t.Fatalf("tampered envelope error = %v, want ErrBadEnvelope", err)
	}
}

func TestDeriveProviderKeySupportsConfiguredKeyLengths(t *testing.T) {
	for _, size := range []int{32, 33, 48, 64} {
		raw := bytes.Repeat([]byte{byte(size)}, size)
		first, err := DeriveProviderKey(raw)
		if err != nil {
			t.Fatalf("DeriveProviderKey(%d) error = %v", size, err)
		}
		if len(first) != derivedKeyLength {
			t.Fatalf("DeriveProviderKey(%d) length = %d, want %d", size, len(first), derivedKeyLength)
		}
		second, err := DeriveProviderKey(raw)
		if err != nil {
			t.Fatalf("DeriveProviderKey(%d) second error = %v", size, err)
		}
		if !bytes.Equal(first, second) {
			t.Fatalf("DeriveProviderKey(%d) is not deterministic", size)
		}
	}
}

func TestDeriveKeySeparatesPurposesAndRejectsShortSources(t *testing.T) {
	raw := bytes.Repeat([]byte{0x52}, 32)
	provider, err := DeriveKey(raw, "provider")
	if err != nil {
		t.Fatalf("DeriveKey(provider): %v", err)
	}
	other, err := DeriveKey(raw, "other")
	if err != nil {
		t.Fatalf("DeriveKey(other): %v", err)
	}
	if bytes.Equal(provider, other) {
		t.Fatal("different derivation purposes produced the same key")
	}
	if _, err := DeriveProviderKey(bytes.Repeat([]byte{0x01}, 31)); !errors.Is(err, ErrSourceKeyLength) {
		t.Fatalf("short source error = %v, want ErrSourceKeyLength", err)
	}
}

func TestEncryptRejectsNonAES256Keys(t *testing.T) {
	for _, size := range []int{16, 24, 31, 33, 64} {
		if _, err := Encrypt(bytes.Repeat([]byte{0x42}, size), 1, []byte("payload")); !errors.Is(err, ErrKeyLength) {
			t.Fatalf("key size %d error = %v, want ErrKeyLength", size, err)
		}
	}
}

func TestEncryptRejectsShortKey(t *testing.T) {
	if _, err := Encrypt([]byte("short"), 1, []byte("payload")); err != ErrKeyLength {
		t.Fatalf("short key error = %v, want ErrKeyLength", err)
	}
}
