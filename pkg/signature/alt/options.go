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

type withContext struct {
	ctx context.Context
}

func (w withContext) applySigner(s *signRequest) {
	s.ctx = w.ctx
}

func (w withContext) applyVerifier(v *verifyRequest) {
	v.ctx = w.ctx
}

func WithContext(ctx context.Context) Option {
	return withContext{ctx}
}

type withRand struct {
	rand io.Reader
}

func (w withRand) applySigner(s *signRequest) {
	s.rand = w.rand
}

func (w withRand) applyVerifier(_ *verifyRequest) {}

// WithRand sets the random number generator to be used when signing a message.
// Has no effect when specified with a Verifier
func WithRand(rand io.Reader) Option {
	return withRand{rand}
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

// WithPSSOptions sets the required PSS options for using the RSA Signer or Verifier
func WithPSSOptions(opts *rsa.PSSOptions) Option {
	return withPSSOptions{opts}
}

type withHashFunc struct {
	hashFunc crypto.Hash
}

func (w withHashFunc) applySigner(s *signRequest) {
	s.hf = w.hashFunc
}

func (w withHashFunc) applyVerifier(v *verifyRequest) {
	v.hf = w.hashFunc
}

// WithHashFunc specifies the hash function to be used
// If WithPSSOptions() is also included in the option list with WithHashFunc(),
// the hash function specified within the PSS Options struct will be used instead.
func WithHashFunc(hashFunc crypto.Hash) Option {
	return withHashFunc{hashFunc}
}

type withDigest struct {
	digest []byte
}

func (w withDigest) applySigner(s *signRequest) {
	s.digest = w.digest
}

func (w withDigest) applyVerifier(v *verifyRequest) {
	v.digest = w.digest
}

// WithDigest specifies the digest to be used when generating the signature, or
// when validating a signature
//
// If omitted during signing, the digest will be computed using the hash function
// configured
func WithDigest(digest []byte) Option {
	return withDigest{digest}
}

type withMessage struct {
	message []byte
}

func (w withMessage) applySigner(_ *signRequest) {}

func (w withMessage) applyVerifier(v *verifyRequest) {
	v.message = w.message
}

// WithMessage specifies the message to verify the signature against.
// This is only used by the ED25519 Verifier, which performs two passes over
// the message in order to verify the signature.
func WithMessage(message []byte) Option {
	return withMessage{message}
}
