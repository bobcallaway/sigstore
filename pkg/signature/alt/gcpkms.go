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
	"io"
	"regexp"

	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"

	"github.com/pkg/errors"
)

type GCPSigner struct {
	BaseKMS
	hf         crypto.Hash
	version    string
	keyVersion kmspb.CryptoKeyVersion
}

var (
	ErrKMSReference = errors.New("kms specification should be in the format gcpkms://projects/[PROJECT_ID]/locations/[LOCATION]/keyRings/[KEY_RING]/cryptoKeys/[KEY]/versions/[VERSION]")

	re = regexp.MustCompile(`^gcpkms://projects/([^/]+)/locations/([^/]+)/keyRings/([^/]+)/cryptoKeys/([^/]+)(?:/versions/([^/]+))?$`)
)

func NewGCPSigner(defaultCtx context.Context, referenceStr string) (*GCPSigner, error) {
	if !re.MatchString(referenceStr) {
		return nil, ErrKMSReference
	}

	return &GCPSigner{
		BaseKMS: BaseKMS{
			defaultCtx: defaultCtx,
			refString:  referenceStr,
		},
	}, nil
}

func (g *GCPSigner) SignMessage(digest []byte, opts ...Option) ([]byte, error) {
	req := &signRequest{
		digest: digest,
	}

	for _, opt := range opts {
		opt.applySigner(req)
	}

	if err := g.validate(req); err != nil {
		return nil, err
	}

	return g.computeSignature(req)
}

func (g *GCPSigner) validate(req *signRequest) error {
	// g.hf must not be crypto.Hash(0)
	if g.hf == crypto.Hash(0) && req.hf == crypto.Hash(0) {
		return errors.New("invalid hash function specified")
	}

	return nil
}

func (g *GCPSigner) computeSignature(req *signRequest) ([]byte, error) {
	hf := req.hf
	if hf == crypto.Hash(0) {
		hf = g.hf
	}

	digest := req.digest
	if digest == nil {
		hasher := hf.New()
		if _, err := hasher.Write(req.message); err != nil {
			return nil, errors.Wrap(err, "hashing during GCP signature")
		}
		digest = hasher.Sum(nil)
	}

	gcpSignReq := kmspb.AsymmetricSignRequest{
		Name:   g.keyVersion.Name,
		Digest: &kmspb.Digest{},
	}

	switch hf {
	case crypto.SHA256:
		gcpSignReq.Digest.Digest = &kmspb.Digest_Sha256{
			Sha256: digest,
		}
	case crypto.SHA384:
		gcpSignReq.Digest.Digest = &kmspb.Digest_Sha384{
			Sha384: digest,
		}
	case crypto.SHA512:
		gcpSignReq.Digest.Digest = &kmspb.Digest_Sha512{
			Sha512: digest,
		}
	default:
		return nil, errors.New("unsupported hash function")
	}

	return nil, nil
}

func (g *GCPSigner) Public() crypto.PublicKey {
	//TODO: implement getting public key
	return nil
}

func (g *GCPSigner) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	return g.SignMessage(digest)
}

type GCPVerifier BaseVerifier

func NewGCPVerifer(pub *ecdsa.PublicKey) (*GCPVerifier, error) {
	return &GCPVerifier{
		pub: pub,
	}, nil
}

func (g GCPVerifier) VerifySignature(signature []byte, opts ...Option) error {
	req := &verifyRequest{
		signature: signature,
	}

	for _, opt := range opts {
		opt.applyVerifier(req)
	}

	if err := g.validate(req); err != nil {
		return err
	}

	return g.verify(req)
}

func (g GCPVerifier) validate(req *verifyRequest) error {
	// req.publicKey must be set
	if g.pub == nil {
		return errors.New("public key is not initialized")
	}
	if _, ok := g.pub.(*ecdsa.PublicKey); !ok {
		return errors.New("public key is not a valid GCP key")
	}

	if req.digest == nil {
		return errors.New("digest is required to verify GCP signature")
	}

	return nil
}

func (g GCPVerifier) verify(req *verifyRequest) error {
	if !ecdsa.VerifyASN1(g.pub.(*ecdsa.PublicKey), req.digest, req.signature) {
		return errors.New("failed to verify signature")
	}
	return nil
}
