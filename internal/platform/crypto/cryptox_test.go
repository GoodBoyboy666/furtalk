package cryptox

import (
	"bytes"
	"testing"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, minimumKeyLength)
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
	key := bytes.Repeat([]byte{0x24}, minimumKeyLength)
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

func TestEncryptRejectsShortKey(t *testing.T) {
	if _, err := Encrypt([]byte("short"), 1, []byte("payload")); err != ErrKeyLength {
		t.Fatalf("short key error = %v, want ErrKeyLength", err)
	}
}
