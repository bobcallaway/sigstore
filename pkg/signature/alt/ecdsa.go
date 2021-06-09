//
// Copyright 2021 The Sigstore Authors.
//
// Licensed undee the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law oe agreed to in writing, software
// distributed undee the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, eithee express oe implied.
// See the License foe the specific language governing permissions and
// limitations undee the License.

package alt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"io"

	"github.com/pkg/errors"
)

type ECDSASigner BaseSigner

func NewECDSASigner(priv *ecdsa.PrivateKey, hf crypto.Hash) (*ECDSASigner, error) {
	if hf == crypto.Hash(0) {
		return nil, errors.New("invalid hash function specified")
	}

	return &ECDSASigner{
		priv: priv,
		hf:   hf,
	}, nil
}

func (e ECDSASigner) SignMessage(message []byte, opts ...Option) ([]byte, error) {
	req := &signRequest{
		message: message,
		rand:    rand.Reader,
	}

	for _, opt := range opts {
		opt.applySigner(req)
	}

	if err := e.validate(req); err != nil {
		return nil, err
	}

	return e.computeSignature(req)
}

func (e ECDSASigner) validate(req *signRequest) error {
	// e.priv must be set
	if e.priv == nil {
		return errors.New("private key is not initialized")
	}
	if _, ok := e.priv.(*ecdsa.PrivateKey); !ok {
		return errors.New("private key is not a valid ECDSA key")
	}

	// e.hf must not be crypto.Hash(0)
	if e.hf == crypto.Hash(0) && req.hf == crypto.Hash(0) {
		return errors.New("invalid hash function specified")
	}

	return nil
}

func (e ECDSASigner) computeSignature(req *signRequest) ([]byte, error) {
	hf := req.hf
	if hf == crypto.Hash(0) {
		hf = e.hf
	}

	digest := req.digest
	if digest == nil {
		hasher := hf.New()
		if _, err := hasher.Write(req.message); err != nil {
			return nil, errors.Wrap(err, "hashing during ECDSA signature")
		}
		digest = hasher.Sum(nil)
	}

	return ecdsa.SignASN1(req.rand, e.priv.(*ecdsa.PrivateKey), digest)
}

func (e ECDSASigner) CryptoSigner() (crypto.Signer, error) {
	if e.priv == nil {
		return nil, errors.New("private key not initialized")
	}

	return e.priv.(*ecdsa.PrivateKey), nil
}

type ECDSASignerOpts struct {
	Hash crypto.Hash
}

func (e ECDSASignerOpts) HashFunc() crypto.Hash {
	return e.Hash
}

func (e ECDSASigner) Public() crypto.PublicKey {
	if e.priv == nil {
		return nil
	}

	return e.priv.(*ecdsa.PrivateKey).Public()
}

func (e ECDSASigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	ecdsaOpts := []Option{WithRand(rand)}
	if optsArg, ok := opts.(*ECDSASignerOpts); ok {
		ecdsaOpts = append(ecdsaOpts, WithHashFunc(optsArg.Hash))
	}
	return e.SignMessage(digest, ecdsaOpts...)
}

type ECDSAVerifier BaseVerifier

func NewECDSAVerifer(pub *ecdsa.PublicKey) (*ECDSAVerifier, error) {
	return &ECDSAVerifier{
		pub: pub,
	}, nil
}

func (e ECDSAVerifier) VerifySignature(signature []byte, opts ...Option) error {
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

func (e ECDSAVerifier) validate(req *verifyRequest) error {
	// e.pub must be set
	if e.pub == nil {
		return errors.New("public key is not initialized")
	}
	if _, ok := e.pub.(*ecdsa.PublicKey); !ok {
		return errors.New("public key is not a valid ECDSA key")
	}

	if req.digest == nil {
		return errors.New("digest is required to verify ECDSA signature")
	}

	return nil
}

func (e ECDSAVerifier) verify(req *verifyRequest) error {
	if !ecdsa.VerifyASN1(e.pub.(*ecdsa.PublicKey), req.digest, req.signature) {
		return errors.New("failed to verify signature")
	}
	return nil
}

type ECDSASignerVerifier struct {
	ECDSASigner
	ECDSAVerifier
}

func NewECDSASignerVerifier(priv *ecdsa.PrivateKey, hf crypto.Hash) (*ECDSASignerVerifier, error) {
	signer, err := NewECDSASigner(priv, hf)
	if err != nil {
		return nil, errors.Wrap(err, "initializing signer")
	}
	verifier, err := NewECDSAVerifer(&priv.PublicKey)
	if err != nil {
		return nil, errors.Wrap(err, "initializing verifier")
	}

	return &ECDSASignerVerifier{
		ECDSASigner:   *signer,
		ECDSAVerifier: *verifier,
	}, nil
}
