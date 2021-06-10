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
	"crypto/rsa"
	"io"
)

// SignerOption configures a Signer.
type SignerOption interface {
	applySigner(s *signRequest)
}

// VerifierOption configures a Verifier.
type VerifierOption interface {
	applyVerifier(v *verifyRequest)
}

// Option configures a Signer or a Verifier.
type Option interface {
	SignerOption
	VerifierOption
}

// Both Signer and Verifier Options

// WithContext specifies the context under which the signing or verification should occur
func WithContext(ctx context.Context) Option {
	return withContext{ctx}
}

type withContext struct {
	ctx context.Context
}

func (w withContext) applySigner(s *signRequest) {
	s.ctx = w.ctx
}

func (w withContext) applyVerifier(v *verifyRequest) {
	v.ctx = w.ctx
}

// WithPSSOptions sets the required PSS options for using the RSA Signer or Verifier
func WithPSSOptions(opts *rsa.PSSOptions) Option {
	return withPSSOptions{opts}
}

type withPSSOptions struct {
	opts *rsa.PSSOptions
}

func (w withPSSOptions) applySigner(s *signRequest) {
	s.pssOpts = w.opts
}

func (w withPSSOptions) applyVerifier(v *verifyRequest) {
	v.pssOpts = w.opts
}

// WithHashFunc specifies the hash function to be used
// If WithPSSOptions() is also included in the option list with WithHashFunc(),
// the hash function specified within the PSS Options struct will be used instead.
func WithHashFunc(hashFunc crypto.Hash) Option {
	return withHashFunc{hashFunc}
}

type withHashFunc struct {
	hashFunc crypto.Hash
}

func (w withHashFunc) applySigner(s *signRequest) {
	s.hashFunc = w.hashFunc
}

func (w withHashFunc) applyVerifier(v *verifyRequest) {
	v.hashFunc = w.hashFunc
}

// Signing-only options

// WithRand sets the random number generator to be used when signing a message.
func WithRand(rand io.Reader) SignerOption {
	return withRand{rand}
}

type withRand struct {
	rand io.Reader
}

func (w withRand) applySigner(s *signRequest) {
	s.rand = w.rand
}

// WithDigest specifies the digest to be used when generating the signature
//
// If omitted during signing, the digest will be computed using the hash function
// configured
func WithDigest(digest []byte) SignerOption {
	return withDigest{digest}
}

type withDigest struct {
	digest []byte
}

func (w withDigest) applySigner(s *signRequest) {
	s.digest = w.digest
}

// Verify-only options

// WithMessage specifies the message to verify the signature against.
// This is only used by the ED25519 Verifier, which performs two passes over
// the message in order to verify the signature.
func WithMessage(message []byte) VerifierOption {
	return withMessage{message}
}

type withMessage struct {
	message []byte
}

func (w withMessage) applyVerifier(v *verifyRequest) {
	v.message = w.message
}
