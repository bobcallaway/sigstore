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
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"io"

	"github.com/pkg/errors"
)

type ECDSASigner struct {
	BaseSigner
	priv *ecdsa.PrivateKey
}

func NewECDSASigner(priv *ecdsa.PrivateKey, hf crypto.Hash) (*ECDSASigner, error) {
	if priv == nil {
		return nil, errors.New("invalid ECDSA private key specified")
	}

	if hf == crypto.Hash(0) {
		return nil, errors.New("invalid hash function specified")
	}

	return &ECDSASigner{
		priv: priv,
		BaseSigner: BaseSigner{
			HashFunc: hf,
		},
	}, nil
}

// SignMessage generates a digital signature for the message provided.
// This method recognizes the following Options listed in order of preference:
// WithDigest()
// WithHashFunc()
// WithRand()
//
// All other options not mentioned here are ignored if specified.
func (e ECDSASigner) SignMessage(message []byte, opts ...SignerOption) ([]byte, error) {
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

	// e.HashFunc must not be crypto.Hash(0)
	if e.HashFunc == crypto.Hash(0) && req.hashFunc == crypto.Hash(0) {
		return errors.New("invalid hash function specified")
	}

	if req.message == nil && req.digest == nil {
		return errors.New("either the message or digest must be provided")
	}

	return nil
}

func (e ECDSASigner) computeSignature(req *signRequest) ([]byte, error) {
	hf := req.hashFunc
	if hf == crypto.Hash(0) {
		hf = e.HashFunc
	}

	digest := req.digest
	if digest == nil {
		hasher := hf.New()
		if _, err := hasher.Write(req.message); err != nil {
			return nil, errors.Wrap(err, "hashing during ECDSA signature")
		}
		digest = hasher.Sum(nil)
	} else if hf.Size() != len(digest) {
		return nil, errors.New("unexpected length of digest for hash function specified")
	}

	return ecdsa.SignASN1(req.rand, e.priv, digest)
}

func (e ECDSASigner) Public() crypto.PublicKey {
	if e.priv == nil {
		return nil
	}

	return e.priv.Public()
}

func (e ECDSASigner) PublicWithContext(_ context.Context) (crypto.PublicKey, error) {
	return e.Public(), nil
}

// Sign signs the digest specified using the private key in ECDSASigner. if a Hash function is
// specified in opts, it will be used instead of the default hasher for the ECDSASigner.
func (e ECDSASigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	ecdsaOpts := []SignerOption{WithRand(rand)}
	if opts != nil {
		ecdsaOpts = append(ecdsaOpts, WithHashFunc(opts.HashFunc()))
	}
	return e.SignMessage(digest, ecdsaOpts...)
}

type ECDSAVerifier struct {
	PublicKey *ecdsa.PublicKey
	Hash      crypto.Hash
}

func NewECDSAVerifier(pub *ecdsa.PublicKey, hashFunc crypto.Hash) (*ECDSAVerifier, error) {
	if pub == nil {
		return nil, errors.New("invalid ECDSA public key specified")
	}

	return &ECDSAVerifier{
		PublicKey: pub,
		Hash:      hashFunc,
	}, nil
}

func (e ECDSAVerifier) VerifySignature(signature []byte, digest []byte, opts ...VerifierOption) error {
	req := &verifyRequest{
		signature: signature,
		digest:    digest,
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
	// e.PublicKey must be set
	if e.PublicKey == nil {
		return errors.New("public key is not initialized")
	}

	if req.digest == nil {
		return errors.New("digest is required to verify ECDSA signature")
	}

	return nil
}

func (e ECDSAVerifier) verify(req *verifyRequest) error {
	if !ecdsa.VerifyASN1(e.PublicKey, req.digest, req.signature) {
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
	verifier, err := NewECDSAVerifier(&priv.PublicKey, hf)
	if err != nil {
		return nil, errors.Wrap(err, "initializing verifier")
	}

	return &ECDSASignerVerifier{
		ECDSASigner:   *signer,
		ECDSAVerifier: *verifier,
	}, nil
}
