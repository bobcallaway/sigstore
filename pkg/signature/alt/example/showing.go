package example

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"errors"

	"github.com/sigstore/sigstore/pkg/signature/alt"
)

func ShowMemorySigners() error {
	rsa, _ := rsa.GenerateKey(rand.Reader, 2048)
	hf := crypto.SHA256
	rsaSV, err := alt.NewRSASignerVerifier(rsa, hf)
	if err != nil {
		return err
	}

	msg := []byte("signme")
	hasher := hf.New()
	_, _ = hasher.Write(msg)
	dig := hasher.Sum(nil)

	sig1, err := rsaSV.SignMessage(msg)
	if err != nil {
		return err
	}
	sig2, err := rsaSV.SignMessage(msg, alt.WithDigest(dig))
	if err != nil {
		return err
	}

	if err := rsaSV.VerifySignature(sig1, alt.WithDigest(dig)); err != nil {
		return err
	}
	if err := rsaSV.VerifySignature(sig2, alt.WithDigest(dig)); err != nil {
		return err
	}
	if err := rsaSV.VerifySignature(sig1); err == nil {
		return errors.New("should have errored due to missing digest")
	}
	return nil
}
