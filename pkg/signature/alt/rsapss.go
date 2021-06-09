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
	"crypto/rand"
	"crypto/rsa"
	"io"

	"github.com/pkg/errors"
)

type RSASigner BaseSigner

func NewRSASigner(priv *rsa.PrivateKey, hf crypto.Hash) (*RSASigner, error) {
	if hf == crypto.Hash(0) {
		return nil, errors.New("invalid hash function specified")
	}

	return &RSASigner{
		priv: priv,
		hf:   hf,
	}, nil
}

// SignMessage recognizes the following Options listed in order of preference:
// WithDigest
// WithPSSOptions()
// WithHashFunc()
// WithRand()
//
// All other options are ignored if specified.
func (r RSASigner) SignMessage(message []byte, opts ...Option) ([]byte, error) {
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

func (r RSASigner) validate(req *signRequest) error {
	// r.priv must be set
	if r.priv == nil {
		return errors.New("private key is not initialized")
	}
	if _, ok := r.priv.(*rsa.PrivateKey); !ok {
		return errors.New("private key is not a valid RSA key")
	}

	// r.hf must not be crypto.Hash(0)
	if r.hf == crypto.Hash(0) && req.pssOpts.Hash == crypto.Hash(0) && req.hf == crypto.Hash(0) {
		return errors.New("invalid hash function specified")
	}

	return nil
}

func (r RSASigner) computeSignature(req *signRequest) ([]byte, error) {
	hf := req.pssOpts.Hash
	if hf == crypto.Hash(0) {
		hf = req.hf
		if hf == crypto.Hash(0) {
			hf = r.hf
		}
	}

	digest := req.digest
	if digest == nil {
		hasher := hf.New()
		if _, err := hasher.Write(req.message); err != nil {
			return nil, errors.Wrap(err, "hashing during RSA signature")
		}
		digest = hasher.Sum(nil)
	}
	// TODO: else: check that digest length == expected length for hf

	return rsa.SignPSS(req.rand, r.priv.(*rsa.PrivateKey), hf, digest, req.pssOpts)
}

func (r RSASigner) CryptoSigner() (crypto.Signer, error) {
	if r.priv == nil {
		return nil, errors.New("private key not initialized")
	}

	return r.priv.(*rsa.PrivateKey), nil
}

func (r RSASigner) Public() crypto.PublicKey {
	if r.priv == nil {
		return nil
	}

	return r.priv.(*rsa.PrivateKey).Public()
}

func (r RSASigner) Sign(rand io.Reader, message []byte, opts crypto.SignerOpts) ([]byte, error) {
	rsaOpts := []Option{WithRand(rand)}
	if optsArg, ok := opts.(*rsa.PSSOptions); ok {
		rsaOpts = append(rsaOpts, WithPSSOptions(optsArg))
	}
	return r.SignMessage(message, rsaOpts...)
}

type RSAVerifier BaseVerifier

func NewRSAVerifer(pub *rsa.PublicKey) (*RSAVerifier, error) {
	return &RSAVerifier{
		pub: pub,
	}, nil
}

func (r RSAVerifier) VerifySignature(signature []byte, opts ...Option) error {
	req := &verifyRequest{
		signature: signature,
	}

	for _, opt := range opts {
		opt.applyVerifier(req)
	}

	if err := r.validate(req); err != nil {
		return err
	}

	return r.verify(req)
}

func (r RSAVerifier) validate(req *verifyRequest) error {
	// r.pub must be set
	if r.pub == nil {
		return errors.New("public key is not initialized")
	}

	if _, ok := r.pub.(*rsa.PublicKey); !ok {
		return errors.New("public key is not a valid RSA key")
	}

	if req.digest == nil {
		return errors.New("digest is required to verify RSA signature")
	}

	// pssOpts.Hash is ignored by VerifyPSS so we don't check it here
	if req.hf == crypto.Hash(0) {
		return errors.New("hash function is required to verify RSA signature")
	}

	return nil
}

func (r RSAVerifier) verify(req *verifyRequest) error {
	return rsa.VerifyPSS(r.pub.(*rsa.PublicKey), req.hf, req.digest, req.signature, req.pssOpts)
}

type RSASignerVerifier struct {
	RSASigner
	RSAVerifier
}

func NewRSASignerVerifier(priv *rsa.PrivateKey, hf crypto.Hash) (*RSASignerVerifier, error) {
	signer, err := NewRSASigner(priv, hf)
	if err != nil {
		return nil, errors.Wrap(err, "initializing signer")
	}
	verifier, err := NewRSAVerifer(&priv.PublicKey)
	if err != nil {
		return nil, errors.Wrap(err, "initializing verifier")
	}

	return &RSASignerVerifier{
		RSASigner:   *signer,
		RSAVerifier: *verifier,
	}, nil
}
