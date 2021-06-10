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
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io"
	"regexp"

	kms "cloud.google.com/go/kms/apiv1"
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"

	"github.com/pkg/errors"
)

type GCPSigner struct {
	BaseKMS
	hf crypto.Hash
	//version    string // TODO: implement this
	keyVersion kmspb.CryptoKeyVersion
	client     *kms.KeyManagementClient
}

var (
	ErrKMSReference = errors.New("kms specification should be in the format gcpkms://projects/[PROJECT_ID]/locations/[LOCATION]/keyRings/[KEY_RING]/cryptoKeys/[KEY]/versions/[VERSION]")

	re = regexp.MustCompile(`^gcpkms://projects/([^/]+)/locations/([^/]+)/keyRings/([^/]+)/cryptoKeys/([^/]+)(?:/versions/([^/]+))?$`)
)

func NewGCPSigner(defaultCtx context.Context, referenceStr string) (*GCPSigner, error) {
	if !re.MatchString(referenceStr) {
		return nil, ErrKMSReference
	}

	if defaultCtx == nil {
		defaultCtx = context.Background()
	}

	g := &GCPSigner{
		BaseKMS: BaseKMS{
			defaultCtx: defaultCtx,
			refString:  referenceStr,
		},
	}

	var err error
	g.client, err = kms.NewKeyManagementClient(defaultCtx)
	if err != nil {
		return nil, errors.Wrap(err, "new gcp kms client")
	}

	return g, nil
}

func (g *GCPSigner) SignMessage(message []byte, opts ...SignerOption) ([]byte, error) {
	req := &signRequest{
		message:  message,
		ctx:      g.defaultCtx,
		hashFunc: g.hf,
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
	if g.hf == crypto.Hash(0) && req.hashFunc == crypto.Hash(0) {
		return errors.New("invalid hash function specified")
	}

	return nil
}

func (g *GCPSigner) computeSignature(req *signRequest) ([]byte, error) {
	hf := req.hashFunc
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
	} else if len(digest) != hf.Size() {
		return nil, errors.New("unexpected length of digest for hash function specified")
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

	resp, err := g.client.AsymmetricSign(req.ctx, &gcpSignReq)
	if err != nil {
		return nil, errors.Wrap(err, "calling GCP AsymmetricSign")
	}

	//TODO: add crc checking

	return resp.Signature, nil
}

// Public returns the current Public Key stored in KMS using the default context;
// if there is an error, this method returns nil
func (g *GCPSigner) Public() crypto.PublicKey {
	pub, _ := g.PublicWithContext(g.defaultCtx)
	// TODO: log err
	return pub
}

// PublicWithContext returns the current Public Key stored in KMS using the specified
// context; if there is an error, this method returns nil
func (g *GCPSigner) PublicWithContext(ctx context.Context) (crypto.PublicKey, error) {
	gcpKeyReq := kmspb.GetPublicKeyRequest{
		Name: g.keyVersion.Name,
	}

	resp, err := g.client.GetPublicKey(ctx, &gcpKeyReq)
	if err != nil {
		return nil, errors.Wrap(err, "GCP GetPublicKey")
	}

	p, _ := pem.Decode([]byte(resp.GetPem()))
	if p == nil {
		return nil, errors.New("pem.Decode failed")
	}

	publicKey, err := x509.ParsePKIXPublicKey(p.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse public key")
	}
	return publicKey, nil
}

// Sign attempts to get the signature for the specified digest using GCP KMS
// This will use the default context set when the GCPSigner was created, unless
// opts are passed to this method of type GCPContextSignerOpts. If a context is
// specified in opts, it will be used instead of the default context on the GCPSigner.
func (g *GCPSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	var gcpOptions []SignerOption
	if opts != nil {
		gcpOptions = append(gcpOptions, WithHashFunc(opts.HashFunc()))
		if ctxOpts, ok := opts.(*GCPContextSignerOpts); ok {
			gcpOptions = append(gcpOptions, WithContext(ctxOpts.Context))
		}
	}
	return g.SignMessage(digest, gcpOptions...)
}

// GCPContextSignerOpts implements crypto.SignerOpts but also allows callers to specify the
// context under which they want the signing transaction to take place.
type GCPContextSignerOpts struct {
	Hash    crypto.Hash
	Context context.Context
}

// HashFunc returns the hash function for this object
func (g GCPContextSignerOpts) HashFunc() crypto.Hash {
	return g.Hash
}

type GCPVerifier struct {
	signer   *GCPSigner       // TODO: replace this when a generic object
	pub      crypto.PublicKey // TODO: deal with key rotation
	hash     crypto.Hash
	verifier Verifier
}

func NewGCPVerifer(defaultCtx context.Context, referenceStr string) (*GCPVerifier, error) {
	g := &GCPVerifier{}

	var err error
	g.signer, err = NewGCPSigner(defaultCtx, referenceStr)
	if err != nil {
		return nil, errors.Wrap(err, "initializing GCP connection")
	}
	g.pub = g.signer.Public()
	if g.pub == nil {
		return nil, errors.New("error fetching public key")
	}

	switch g.signer.keyVersion.Algorithm {
	case kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256:
		g.hash = crypto.SHA256
		g.verifier, err = NewECDSAVerifier(g.pub.(*ecdsa.PublicKey), g.hash)
	case kmspb.CryptoKeyVersion_EC_SIGN_P384_SHA384:
		g.hash = crypto.SHA384
		g.verifier, err = NewECDSAVerifier(g.pub.(*ecdsa.PublicKey), g.hash)
	case kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256,
		kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_3072_SHA256,
		kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA256:
		g.hash = crypto.SHA256
		g.verifier, err = NewRSAPKCS1v15Verifier(g.pub.(*rsa.PublicKey), g.hash)
	case kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA512:
		g.hash = crypto.SHA512
		g.verifier, err = NewRSAPKCS1v15Verifier(g.pub.(*rsa.PublicKey), g.hash)
	case kmspb.CryptoKeyVersion_RSA_SIGN_PSS_2048_SHA256,
		kmspb.CryptoKeyVersion_RSA_SIGN_PSS_3072_SHA256,
		kmspb.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA256:
		g.hash = crypto.SHA256
		g.verifier, err = NewRSAPSSVerifier(g.pub.(*rsa.PublicKey), g.hash)
	case kmspb.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA512:
		g.hash = crypto.SHA512
		g.verifier, err = NewRSAPSSVerifier(g.pub.(*rsa.PublicKey), g.hash)
	default:
		return nil, errors.New("unsupported signing algorithm")
	}
	if err != nil {
		return nil, errors.Wrap(err, "initializing verifier")
	}

	return g, nil
}

func (g GCPVerifier) VerifySignature(signature []byte, digest []byte, opts ...VerifierOption) error {
	return g.verifier.VerifySignature(signature, digest, opts...)
}
