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
	"context"
	"crypto"
	"crypto/ed25519"
	"io"

	"github.com/pkg/errors"
)

type ED25519Signer struct {
	priv *ed25519.PrivateKey
}

func NewED25519Signer(priv *ed25519.PrivateKey) (*ED25519Signer, error) {
	if priv == nil {
		return nil, errors.New("invalid ED25519 private key specified")
	}

	return &ED25519Signer{
		priv: priv,
	}, nil
}

// SignMessage generates the signature for the message using the ED25519 key
//
// All options are ignored by this function.
func (e ED25519Signer) SignMessage(message []byte, _ ...SignerOption) ([]byte, error) {
	req := &signRequest{
		message: message,
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

	return nil
}

func (e ED25519Signer) computeSignature(req *signRequest) ([]byte, error) {
	return ed25519.Sign(*e.priv, req.message), nil
}

func (e ED25519Signer) CryptoSigner() (crypto.Signer, error) {
	if e.priv == nil {
		return nil, errors.New("private key not initialized")
	}

	return e.priv, nil
}

func (e ED25519Signer) Public() crypto.PublicKey {
	if e.priv == nil {
		return nil
	}

	return e.priv.Public()
}

func (e ED25519Signer) PublicWithContext(_ context.Context) (crypto.PublicKey, error) {
	return e.Public(), nil
}

func (e ED25519Signer) Sign(_ io.Reader, message []byte, _ crypto.SignerOpts) ([]byte, error) {
	return e.SignMessage(message)
}

type ED25519Verifier struct {
	PublicKey *ed25519.PublicKey
}

func NewED25519Verifer(pub *ed25519.PublicKey) (*ED25519Verifier, error) {
	if pub == nil {
		return nil, errors.New("invalid ED25519 public key specified")
	}

	return &ED25519Verifier{
		PublicKey: pub,
	}, nil
}

// VerifySignature verifies the signature against the message specified in the
// WithMessage() option
func (e ED25519Verifier) VerifySignature(signature []byte, _ []byte, opts ...VerifierOption) error {
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
	// e.PublicKey must be set
	if e.PublicKey == nil {
		return errors.New("public key is not initialized")
	}

	if req.message == nil {
		return errors.New("message must be specified in WithMessage() option")
	}

	return nil
}

func (e ED25519Verifier) verify(req *verifyRequest) error {
	if !ed25519.Verify(*e.PublicKey, req.message, req.signature) {
		return errors.New("failed to verify signature")
	}
	return nil
}

type ED25519SignerVerifier struct {
	ED25519Signer
	ED25519Verifier
}

func NewED25519SignerVerifier(priv *ed25519.PrivateKey) (*ED25519SignerVerifier, error) {
	signer, err := NewED25519Signer(priv)
	if err != nil {
		return nil, errors.Wrap(err, "initializing signer")
	}
	pub := priv.Public().(ed25519.PublicKey)
	verifier, err := NewED25519Verifer(&pub)
	if err != nil {
		return nil, errors.Wrap(err, "initializing verifier")
	}

	return &ED25519SignerVerifier{
		ED25519Signer:   *signer,
		ED25519Verifier: *verifier,
	}, nil
}
