package example

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"

	"github.com/sigstore/sigstore/pkg/signature/alt"
)

func ShowMemorySigners() error {
	rsa, _ := rsa.GenerateKey(rand.Reader, 2048)
	hf := crypto.SHA512
	rsaSV, err := alt.NewRSAPSSSignerVerifier(rsa, hf)
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

	if err := rsaSV.VerifySignature(sig1, dig, alt.WithHashFunc(hf)); err != nil {
		return err
	}

	edKey := ed25519.NewKeyFromSeed([]byte("seedseedseedseedseedseedseedseed"))
	edSV, err := alt.NewED25519SignerVerifier(&edKey)
	if err != nil {
		return err
	}

	edSig, err := edSV.SignMessage(msg)
	if err != nil {
		return err
	}

	// ED25519 needs the message, not a digest, so this is a bit yucky
	if err := edSV.VerifySignature(edSig, nil, alt.WithMessage(msg)); err != nil {
		return err
	}

	gcpKMS, err := alt.NewGCPSigner(context.Background(), "gcpkms://something")
	if err != nil {
		return err
	}

	if _, err := gcpKMS.SignMessage(msg, alt.WithContext(context.Background())); err != nil {
		return err
	}

	return nil
}
