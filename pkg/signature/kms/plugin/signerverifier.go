//
// Copyright 2024 The Sigstore Authors.
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

package plugin

import (
	"context"
	"crypto"
	"fmt"
	"io"
	"slices"
	"strings"

	v1 "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/kms/plugin/generated"
	"github.com/sigstore/sigstore/pkg/signature/options"
	"google.golang.org/grpc"
)

// SignerVerifier creates and verifies digital signatures via a plugin over a gRPC channel
type SignerVerifier struct {
	defaultCtx          context.Context
	client              generated.KMSPluginClient
	supportedAlgorithms []string
	defaultAlgorithm    string
}

// LoadSignerVerifier generates signatures using the plugin reachable over gRPC channel.
//
// the only opts respected by this call are GRPCDialOpts
func LoadSignerVerifier(defaultCtx context.Context, referenceStr string, opts ...signature.RPCOption) (*SignerVerifier, error) {
	//extract target from referenceStr
	target, found := strings.CutPrefix(referenceStr, ReferenceSchemePrefix)
	if !found {
		return nil, fmt.Errorf("%s is missing the correct prefix %s", referenceStr, ReferenceSchemePrefix)
	}

	dialOpts := make([]grpc.DialOption, len(opts))
	for i, opt := range opts {
		opt.ApplyGRPCDialOpts(&dialOpts[i])
	}
	dialOpts = slices.Clip(slices.DeleteFunc(dialOpts, func(dialOpt grpc.DialOption) bool { return dialOpt == nil }))

	cc, err := grpc.DialContext(defaultCtx, target, dialOpts...)
	if err != nil {
		return nil, err
	}

	sv := &SignerVerifier{
		defaultCtx: defaultCtx,
		client:     generated.NewKMSPluginClient(cc),
	}

	// since these should not change during the life of a client, we cache them locally, as well as use this as a test of connectivity
	// to the server instance
	saResponse, err := sv.client.SupportedAlgorithms(defaultCtx, &generated.SupportedAlgorithmsRequest{})
	if err != nil {
		return nil, err
	}
	sv.supportedAlgorithms = saResponse.Algorithms

	daResponse, err := sv.client.DefaultAlgorithm(defaultCtx, &generated.DefaultAlgorithmRequest{})
	if err != nil {
		return nil, err
	}
	sv.defaultAlgorithm = daResponse.Algorithm

	return sv, nil

}

// SignMessage signs the provided message using a gRPC plugin. If the message is provided,
// this method will compute the digest according to the hash function specified
// when the Signer was created.
//
// SignMessage recognizes the following Options listed in order of preference:
//
// - WithContext()
//
// - WithDigest()
//
// - WithCryptoSignerOpts()
//
// All other options are ignored if specified.
func (sv *SignerVerifier) SignMessage(message io.Reader, opts ...signature.SignOption) ([]byte, error) {
	ctx := context.Background()
	var digest []byte
	var signerOpts crypto.SignerOpts
	var err error

	for _, opt := range opts {
		opt.ApplyContext(&ctx)
		opt.ApplyDigest(&digest)
		opt.ApplyCryptoSignerOpts(&signerOpts)
	}

	hashFuncEnum := map[crypto.Hash]v1.HashAlgorithm{
		0:               v1.HashAlgorithm_HASH_ALGORITHM_UNSPECIFIED,
		crypto.SHA256:   v1.HashAlgorithm_SHA2_256,
		crypto.SHA384:   v1.HashAlgorithm_SHA2_384,
		crypto.SHA512:   v1.HashAlgorithm_SHA2_512,
		crypto.SHA3_256: v1.HashAlgorithm_SHA3_256,
		crypto.SHA3_384: v1.HashAlgorithm_SHA3_384,
	}[signerOpts.HashFunc()]

	request := generated.SignMessageRequest{}
	if digest != nil {
		// lookup v1.HashAlgorithm for hash function
		request.Input = &generated.SignMessageRequest_HashOutput{
			HashOutput: &v1.HashOutput{
				Algorithm: hashFuncEnum,
				Digest:    digest,
			},
		}
	} else {
		messageBytes, err := io.ReadAll(message)
		if err != nil {
			return nil, fmt.Errorf("reading message: %w")
		}

		request.Input = &generated.SignMessageRequest_Message{
			Message: messageBytes,
		}
	}

	signerOpts, err = sv.client.getHashFunc()
	if err != nil {
		return nil, fmt.Errorf("getting fetching default hash function: %w", err)
	}

	digest, hf, err := signature.ComputeDigestForSigning(message, signerOpts.HashFunc(), gcpSupportedHashFuncs, opts...)
	if err != nil {
		return nil, err
	}

	return sv.client.sign(ctx, digest, hf, crc32cHasher.Sum32())
}

// PublicKey returns the public key that can be used to verify signatures created by
// this signer. If the caller wishes to specify the context to use to obtain
// the public key, pass option.WithContext(desiredCtx).
//
// All other options are ignored if specified.
func (sv *SignerVerifier) PublicKey(opts ...signature.PublicKeyOption) (crypto.PublicKey, error) {
	ctx := context.Background()
	for _, opt := range opts {
		opt.ApplyContext(&ctx)
	}

	return sv.client.public(ctx)
}

// VerifySignature verifies the signature for the given message. Unless provided
// in an option, the digest of the message will be computed using the hash function specified
// when the SignerVerifier was created.
//
// This function returns nil if the verification succeeded, and an error message otherwise.
//
// This function recognizes the following Options listed in order of preference:
//
// - WithDigest()
//
// All other options are ignored if specified.
func (sv *SignerVerifier) VerifySignature(signature, message io.Reader, opts ...signature.VerifyOption) error {
	return sv.client.verify(signature, message, opts...)
}

// CreateKey attempts to create a new key in Vault with the specified algorithm.
func (sv *SignerVerifier) CreateKey(ctx context.Context, algorithm string) (crypto.PublicKey, error) {
	return sv.client.createKey(ctx, algorithm)
}

type cryptoSignerWrapper struct {
	ctx      context.Context
	hashFunc crypto.Hash
	sv       *SignerVerifier
	errFunc  func(error)
}

func (c cryptoSignerWrapper) Public() crypto.PublicKey {
	pk, err := c.sv.PublicKey(options.WithContext(c.ctx))
	if err != nil && c.errFunc != nil {
		c.errFunc(err)
	}
	return pk
}

func (c cryptoSignerWrapper) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	hashFunc := c.hashFunc
	if opts != nil {
		hashFunc = opts.HashFunc()
	}
	gcpOptions := []signature.SignOption{
		options.WithContext(c.ctx),
		options.WithDigest(digest),
		options.WithCryptoSignerOpts(hashFunc),
	}

	return c.sv.SignMessage(nil, gcpOptions...)
}

// CryptoSigner returns a crypto.Signer object that uses the underlying SignerVerifier, along with a crypto.SignerOpts object
// that allows the KMS to be used in APIs that only accept the standard golang objects
func (sv *SignerVerifier) CryptoSigner(ctx context.Context, errFunc func(error)) (crypto.Signer, crypto.SignerOpts, error) {
	defaultHf, err := sv.client.getHashFunc()
	if err != nil {
		return nil, nil, fmt.Errorf("getting fetching default hash function: %w", err)
	}

	csw := &cryptoSignerWrapper{
		ctx:      ctx,
		sv:       sv,
		hashFunc: defaultHf,
		errFunc:  errFunc,
	}

	return csw, defaultHf, nil
}

// SupportedAlgorithms returns the list of algorithms supported by the KMS plugin
func (sv *SignerVerifier) SupportedAlgorithms() []string {
	return sv.supportedAlgorithms
}

// DefaultAlgorithm returns the default algorithm for the KMS plugin
func (sv *SignerVerifier) DefaultAlgorithm() string {
	return sv.defaultAlgorithm
}
