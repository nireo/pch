package pch

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"path"
	"testing"
)

func TestOtpFull(t *testing.T) {
	const nkeys = 64
	otps := make(map[[32]byte]*ecdh.PrivateKey)

	for range nkeys {
		privKey, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate private key: %v", err)
		}
		var pubKeyArr [32]byte
		copy(pubKeyArr[:], privKey.PublicKey().Bytes())
		otps[pubKeyArr] = privKey
	}
	fpath := path.Join(t.TempDir(), "otp_test")

	err := DumpOtpFile(otps, fpath)
	if err != nil {
		t.Fatalf("DumpOtpFile failed: %v", err)
	}

	readOtps, err := ReadOtpFile(fpath)
	if err != nil {
		t.Fatalf("ReadOtpFile failed: %v", err)
	}

	if len(readOtps) != len(otps) {
		t.Fatalf("expected %d OTPs, got %d", len(otps), len(readOtps))
	}

	for k, v := range otps {
		readPrivKey, exists := readOtps[k]
		if !exists {
			t.Fatalf("OTP for key %x not found in read data", k)
		}
		if !bytes.Equal(v.Bytes(), readPrivKey.Bytes()) {
			t.Fatalf("OTP private key mismatch for key %x", k)
		}
	}
}
