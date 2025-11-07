package pch

import (
	"crypto/ecdh"
	"crypto/mlkem"
	"fmt"
)

type queue[T any] []T

func (q *queue[T]) enqueue(val T) {
	*q = append(*q, val)
}

func (q *queue[T]) dequeue() (T, error) {
	if len(*q) == 0 {
		var zero T
		return zero, fmt.Errorf("queue is empty")
	}
	value := (*q)[0]
	*q = (*q)[1:]
	return value, nil
}

type oneTimeKEMKey struct {
	decap *mlkem.DecapsulationKey1024
	encap *mlkem.EncapsulationKey1024
}

type oneTimePreKey struct {
	sk *ecdh.PrivateKey
	pk *ecdh.PublicKey
}

type pqxdhBundle struct {
	encap    *mlkem.EncapsulationKey1024
	encapSig []byte

	otpk    *ecdh.PublicKey
	otpkSig []byte

	idpk   *ecdh.PublicKey
	spkpk  *ecdh.PublicKey
	spkSig []byte
}

type pqxdhState struct {
	idsk           *ecdh.PrivateKey
	idpk           *ecdh.PublicKey
	signedPrekeySK *ecdh.PrivateKey
	signedPrekeyPK *ecdh.PublicKey

	// this is used when no oneTimeKEM keys are available
	lastResortKEMkey *mlkem.DecapsulationKey1024
	oneTimeKEMKeys   queue[oneTimeKEMKey]
	oneTimePreKeys   queue[oneTimePreKey]
}

func (ps *pqxdhState) keyExchange(bundle *pqxdhBundle) ([]byte, error) {
	return nil, nil
}
