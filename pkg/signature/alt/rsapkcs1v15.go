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
	"crypto/rand"
	"crypto/rsa"
	"io"

	"github.com/pkg/errors"
)

type RSAPKCS1v15Signer struct {
	BaseSigner
	priv *rsa.PrivateKey
}

func NewRSAPKCS1v15Signer(priv *rsa.PrivateKey, hf crypto.Hash) (*RSAPKCS1v15Signer, error) {
	if priv == nil {
		return nil, errors.New("invalid RSA private key specified")
	}

	if hf == crypto.Hash(0) {
		return nil, errors.New("invalid hash function specified")
	}

	return &RSAPKCS1v15Signer{
		priv: priv,
		BaseSigner: BaseSigner{
			HashFunc: hf,
		},
	}, nil
}

// SignMessage recognizes the following Options listed in order of preference:
// WithRand()
// WithDigest()
// WithPSSOptions()
// WithHashFunc()
//
// All other options are ignored if specified.
func (r RSAPKCS1v15Signer) SignMessage(message []byte, opts ...SignerOption) ([]byte, error) {
	req := &signRequest{
		message: message,
		rand:    rand.Reader,
	}

	for _, opt := range opts {
		opt.applySigner(req)
	}

	if err := r.validate(req); err != nil {
		return nil, err
	}

	return r.computeSignature(req)
}

func (r RSAPKCS1v15Signer) validate(req *signRequest) error {
	// r.priv must be set
	if r.priv == nil {
		return errors.New("private key is not initialized")
	}

	// r.HashFunc must not be crypto.Hash(0)
	if r.HashFunc == crypto.Hash(0) && req.hashFunc == crypto.Hash(0) {
		return errors.New("invalid hash function specified")
	}

	return nil
}

func (r RSAPKCS1v15Signer) computeSignature(req *signRequest) ([]byte, error) {
	hf := req.hashFunc
	if hf == crypto.Hash(0) {
		hf = r.HashFunc
	}

	digest := req.digest
	if digest == nil {
		hasher := hf.New()
		if _, err := hasher.Write(req.message); err != nil {
			return nil, errors.Wrap(err, "hashing during RSA signature")
		}
		digest = hasher.Sum(nil)
	} else {
		if hf.Size() != len(digest) {
			return nil, errors.New("unexpected length of digest for hash functions specified")
		}
	}

	return rsa.SignPKCS1v15(req.rand, r.priv, hf, digest)
}

func (r RSAPKCS1v15Signer) Public() crypto.PublicKey {
	if r.priv == nil {
		return nil
	}

	return r.priv.Public()
}

func (r RSAPKCS1v15Signer) PublicWithContext(_ context.Context) (crypto.PublicKey, error) {
	return r.Public(), nil
}

func (r RSAPKCS1v15Signer) Sign(rand io.Reader, message []byte, opts crypto.SignerOpts) ([]byte, error) {
	rsaOpts := []SignerOption{WithRand(rand)}
	if opts != nil {
		rsaOpts = append(rsaOpts, WithHashFunc(opts.HashFunc()))
		if optsArg, ok := opts.(*rsa.PSSOptions); ok {
			rsaOpts = append(rsaOpts, WithPSSOptions(optsArg))
		}
	}
	return r.SignMessage(message, rsaOpts...)
}

type RSAPKCS1v15Verifier struct {
	PublicKey *rsa.PublicKey
	Hash      crypto.Hash
}

func NewRSAPKCS1v15Verifier(pub *rsa.PublicKey, hashFunc crypto.Hash) (*RSAPKCS1v15Verifier, error) {
	if pub == nil {
		return nil, errors.New("invalid RSA public key specified")
	}

	if hashFunc == crypto.Hash(0) {
		return nil, errors.New("invalid hash function specified")
	}

	return &RSAPKCS1v15Verifier{
		PublicKey: pub,
		Hash:      hashFunc,
	}, nil
}

func (r RSAPKCS1v15Verifier) VerifySignature(signature []byte, digest []byte, opts ...VerifierOption) error {
	req := &verifyRequest{
		signature: signature,
		digest:    digest,
		hashFunc:  r.Hash,
	}

	for _, opt := range opts {
		opt.applyVerifier(req)
	}

	if err := r.validate(req); err != nil {
		return err
	}

	return r.verify(req)
}

func (r RSAPKCS1v15Verifier) validate(req *verifyRequest) error {
	// r.PublicKey must be set
	if r.PublicKey == nil {
		return errors.New("public key is not initialized")
	}

	if req.digest == nil {
		return errors.New("digest is required to verify RSA signature")
	}

	// pssOpts.Hash is ignored by VerifyPSS so we don't check it here
	if req.hashFunc == crypto.Hash(0) {
		return errors.New("hash function is required to verify RSA signature")
	}

	return nil
}

func (r RSAPKCS1v15Verifier) verify(req *verifyRequest) error {
	return rsa.VerifyPSS(r.PublicKey, req.hashFunc, req.digest, req.signature, req.pssOpts)
}

type RSAPKCS1v15SignerVerifier struct {
	RSAPKCS1v15Signer
	RSAPKCS1v15Verifier
}

func NewRSAPKCS1v15SignerVerifier(priv *rsa.PrivateKey, hf crypto.Hash) (*RSAPKCS1v15SignerVerifier, error) {
	signer, err := NewRSAPKCS1v15Signer(priv, hf)
	if err != nil {
		return nil, errors.Wrap(err, "initializing signer")
	}
	verifier, err := NewRSAPKCS1v15Verifier(&priv.PublicKey, hf)
	if err != nil {
		return nil, errors.Wrap(err, "initializing verifier")
	}

	return &RSAPKCS1v15SignerVerifier{
		RSAPKCS1v15Signer:   *signer,
		RSAPKCS1v15Verifier: *verifier,
	}, nil
}
