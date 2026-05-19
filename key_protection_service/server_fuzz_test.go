// Copyright 2026 Google LLC
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

package keyprotectionservice

import (
	"context"
	"testing"

	kpspb "github.com/GoogleCloudPlatform/key-protection-module/key_protection_service/proto"
	keymanager "github.com/GoogleCloudPlatform/key-protection-module/km_common/proto"
	"github.com/google/uuid"
)

func FuzzGetKeyClaims(f *testing.F) {
	f.Add("00000000-0000-0000-0000-000000000000", int32(keymanager.KeyType_KEY_TYPE_VM_PROTECTION_KEY), int32(keymanager.KeyProtectionMechanism_KEY_PROTECTION_VM), int32(keymanager.ServiceRole_SERVICE_ROLE_KPS))
	f.Add("invalid-uuid", int32(0), int32(0), int32(0))

	f.Fuzz(func(t *testing.T, handle string, keyType int32, mode int32, role int32) {
		// We use mockKPS for GetKeyClaims fuzzing as it mostly tests Go-side validation and routing
		mock := &mockKPS{
			GetKEMKeyFn: func(_ context.Context, id uuid.UUID) ([]byte, []byte, *keymanager.HpkeAlgorithm, uint64, error) {
				return []byte("kem-pub"), []byte("binding-pub"), &keymanager.HpkeAlgorithm{Kem: keymanager.KemAlgorithm_KEM_ALGORITHM_DHKEM_X25519_HKDF_SHA256}, 100, nil
			},
		}

		srv := &Server{
			kps:  mock,
			mode: keymanager.KeyProtectionMechanism(mode),
			role: keymanager.ServiceRole(role),
		}

		req := &keymanager.GetKeyClaimsRequest{
			KeyHandle: &keymanager.KeyHandle{Handle: handle},
			KeyType:   keymanager.KeyType(keyType),
		}

		_, _ = srv.GetKeyClaims(context.Background(), req)
	})
}

func FuzzGenerateKEMKeypair(f *testing.F) {
	f.Add(int32(keymanager.KemAlgorithm_KEM_ALGORITHM_DHKEM_X25519_HKDF_SHA256), []byte("binding-pub-key-bytes-must-be-32-bytes-long"), uint64(3600))
	f.Add(int32(0), []byte("short"), uint64(0))

	f.Fuzz(func(t *testing.T, kemAlgo int32, bindingPubKey []byte, lifespan uint64) {
		// Use real defaultKPS to fuzz Rust FFI layer
		realKps := &defaultKPS{}
		srv := &grpcServer{
			svc:       realKps,
			bootToken: "fuzz-token",
		}

		req := &kpspb.GenerateKEMKeypairRequest{
			Algo: &keymanager.HpkeAlgorithm{
				Kem:  keymanager.KemAlgorithm(kemAlgo),
				Kdf:  keymanager.KdfAlgorithm_KDF_ALGORITHM_HKDF_SHA256,
				Aead: keymanager.AeadAlgorithm_AEAD_ALGORITHM_AES_256_GCM,
			},
			BindingPubKey: &keymanager.HpkePublicKey{
				Algorithm: &keymanager.HpkeAlgorithm{
					Kem:  keymanager.KemAlgorithm(kemAlgo),
					Kdf:  keymanager.KdfAlgorithm_KDF_ALGORITHM_HKDF_SHA256,
					Aead: keymanager.AeadAlgorithm_AEAD_ALGORITHM_AES_256_GCM,
				},
				PublicKey: bindingPubKey,
			},
			LifespanSecs: lifespan,
		}

		// We also run validation interceptor to make it more realistic and test validation
		_, _ = ValidationInterceptor(context.Background(), req, nil, func(ctx context.Context, r interface{}) (interface{}, error) {
			return srv.GenerateKEMKeypair(ctx, r.(*kpspb.GenerateKEMKeypairRequest))
		})
	})
}

func FuzzDecapAndSeal(f *testing.F) {
	f.Add("00000000-0000-0000-0000-000000000000", []byte("ciphertext"), []byte("aad"))
	f.Add("invalid-uuid", []byte(""), []byte(""))

	f.Fuzz(func(t *testing.T, handle string, ciphertext []byte, aad []byte) {
		realKps := &defaultKPS{}
		srv := &grpcServer{
			svc:       realKps,
			bootToken: "fuzz-token",
		}

		req := &kpspb.DecapAndSealRequest{
			KeyHandle: &keymanager.KeyHandle{Handle: handle},
			Ciphertext: &keymanager.KemCiphertext{
				Algorithm:  keymanager.KemAlgorithm_KEM_ALGORITHM_DHKEM_X25519_HKDF_SHA256,
				Ciphertext: ciphertext,
			},
			Aad: aad,
		}

		// Pre-generate a key if we want to test successful decaps, but since GenerateKEMKeypair
		// requires a valid binding key from WSD, it's hard to do it fully hermetically here
		// without mocking.
		// However, fuzzing the error paths of DecapAndSeal FFI is still very valuable.
		// We can occasionally inject a valid UUID if we had one, but here we just fuzz the input.
		// Rust FFI should handle invalid UUIDs and invalid ciphertexts gracefully without crashing.

		_, _ = ValidationInterceptor(context.Background(), req, nil, func(ctx context.Context, r interface{}) (interface{}, error) {
			return srv.DecapAndSeal(ctx, r.(*kpspb.DecapAndSealRequest))
		})
	})
}
