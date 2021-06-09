//
// Copyright 2021 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package alt

import (
	"crypto"
	"crypto/ed25519"
	"io"

	"github.com/pkg/errors"
)

type ED25519Signer BaseSigner

func NewED25519Signer(priv *ed25519.PrivateKey) (*ED25519Signer, error) {
	return &ED25519Signer{
		priv: priv,
	}, nil
}

func (e ED25519Signer) SignMessage(message []byte, opts ...Option) ([]byte, error) {
	req := &signRequest{
		message: message,
	}

	for _, opt := range opts {
		opt.applySigner(req)
	}

	if err := e.validate(req); err != nil {
		return nil, err
	}

	return e.computeSignature(req)
}

func (e ED25519Signer) validate(req *signRequest) error {
	// e.priv must be set
	if e.priv == nil {
		return errors.New("private key is not initialized")
	}
	if _, ok := e.priv.(*ed25519.PrivateKey); !ok {
		return errors.New("private key is not a valid ED25519 key")
	}

	return nil
}

func (e ED25519Signer) computeSignature(req *signRequest) ([]byte, error) {
	return ed25519.Sign(*e.priv.(*ed25519.PrivateKey), req.message), nil
}

func (e ED25519Signer) CryptoSigner() (crypto.Signer, error) {
	if e.priv == nil {
		return nil, errors.New("private key not initialized")
	}

	return e.priv.(*ed25519.PrivateKey), nil
}

func (e ED25519Signer) Public() crypto.PublicKey {
	if e.priv == nil {
		return nil
	}

	return e.priv.(*ed25519.PrivateKey).Public()
}

func (e ED25519Signer) Sign(_ io.Reader, message []byte, _ crypto.SignerOpts) ([]byte, error) {
	return e.SignMessage(message)
}

type ED25519Verifier BaseVerifier

func NewED25519Verifer(pub *ed25519.PublicKey) (*ED25519Verifier, error) {
	return &ED25519Verifier{
		pub: pub,
	}, nil
}

func (e ED25519Verifier) VerifySignature(signature []byte, opts ...Option) error {
	req := &verifyRequest{
		signature: signature,
	}

	for _, opt := range opts {
		opt.applyVerifier(req)
	}

	if err := e.validate(req); err != nil {
		return err
	}

	return e.verify(req)
}

func (e ED25519Verifier) validate(req *verifyRequest) error {
	// req.publicKey must be set
	if e.pub == nil {
		return errors.New("public key is not initialized")
	}
	if _, ok := e.pub.(*ed25519.PublicKey); !ok {
		return errors.New("public key is not a valid ED25519 key")
	}

	return nil
}

func (e ED25519Verifier) verify(req *verifyRequest) error {
	if !ed25519.Verify(*e.pub.(*ed25519.PublicKey), req.message, req.signature) {
		return errors.New("failed to verify signature")
	}
	return nil
}

type ED25519SignerVerifier struct {
	ED25519Signer
	ED25519Verifier
}

func NewED25519SignerVerifier(priv *ed25519.PrivateKey, hf crypto.Hash) (*ED25519SignerVerifier, error) {
	signer, err := NewED25519Signer(priv)
	if err != nil {
		return nil, errors.Wrap(err, "initializing signer")
	}
	verifier, err := NewED25519Verifer(priv.Public().(*ed25519.PublicKey))
	if err != nil {
		return nil, errors.Wrap(err, "initializing verifier")
	}

	return &ED25519SignerVerifier{
		ED25519Signer:   *signer,
		ED25519Verifier: *verifier,
	}, nil
}
