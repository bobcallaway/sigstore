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

	"github.com/sigstore/sigstore/pkg/signature"
	sigkms "github.com/sigstore/sigstore/pkg/signature/kms"
)

func init() {
	sigkms.AddProvider(ReferenceSchemePrefix, func(ctx context.Context, keyResourceID string, _ crypto.Hash, opts ...signature.RPCOption) (sigkms.SignerVerifier, error) {
		return LoadSignerVerifier(ctx, keyResourceID, opts...)
	})
}

// ReferenceSchemePrefix scheme for plugin service assumes a prefix of 'plugin://' followed by a valid gRPC URI
const ReferenceSchemePrefix = "plugin://"
