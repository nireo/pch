package pch

import (
	"crypto/ecdh"
	"fmt"
	"os"
	"path/filepath"
)

// DefaultOtpPath is the default path for storing OTPs.
const DefaultOtpPath = ".config/pch/otps"

// ensureOtpFile makes sure the OTP file exists, creating it if necessary. the caller is responsible
// for closing the file.
func ensureOtpFile(path string) (*os.File, error) {
	// ensure the directory exists
	err := os.MkdirAll(filepath.Dir(path), 0700)
	if err != nil {
		return nil, fmt.Errorf("failed to create otp directory: %w", err)
	}

	return os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0644)
}

// DumpOtpFile writes the given OTP map to the OTP file.
func DumpOtpFile(otps map[[32]byte]*ecdh.PrivateKey, path string) error {
	encodingSafe := make(map[[32]byte][]byte)
	for k, v := range otps {
		encodingSafe[k] = v.Bytes()
	}

	data, err := encodeGob(encodingSafe)
	if err != nil {
		return fmt.Errorf("failed to encode otp data: %w", err)
	}

	f, err := ensureOtpFile(path)
	if err != nil {
		return fmt.Errorf("failed to open otp file: %w", err)
	}
	defer f.Close()

	err = f.Truncate(0)
	if err != nil {
		return fmt.Errorf("failed to truncate otp file: %w", err)
	}

	_, err = f.Write(data)
	return err
}

// ReadOtpFile reads the OTP map from the OTP file.
func ReadOtpFile(path string) (map[[32]byte]*ecdh.PrivateKey, error) {
	encodedOtps := make(map[[32]byte][]byte)

	f, err := ensureOtpFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open otp file: %w", err)
	}
	defer f.Close()

	fileInfo, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("failed to stat otp file: %w", err)
	}

	if fileInfo.Size() == 0 {
		return make(map[[32]byte]*ecdh.PrivateKey), nil
	}

	data := make([]byte, fileInfo.Size())
	_, err = f.Read(data)
	if err != nil {
		return nil, fmt.Errorf("failed to read otp file: %w", err)
	}

	err = decodeGob(data, &encodedOtps)
	if err != nil {
		return nil, fmt.Errorf("failed to decode otp data: %w", err)
	}

	otps := make(map[[32]byte]*ecdh.PrivateKey, len(encodedOtps))
	for k, v := range encodedOtps {
		privKey, err := ecdh.X25519().NewPrivateKey(v)
		if err != nil {
			return nil, fmt.Errorf("failed to reconstruct private key: %w", err)
		}
		otps[k] = privKey
	}

	return otps, nil
}
