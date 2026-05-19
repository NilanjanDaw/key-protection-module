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

package workloadservice

import (
	"reflect"
	"strings"
	"testing"

	keymanager "github.com/GoogleCloudPlatform/key-protection-module/km_common/proto"
	kpspb "github.com/GoogleCloudPlatform/key-protection-module/key_protection_service/proto"
	api "github.com/GoogleCloudPlatform/key-protection-module/workload_service/proto"
)

func TestProtoFieldAlignment(t *testing.T) {
	// Exemptions: Fields that are intentionally different between the two APIs.
	// Any new field added to api.KeyInfo MUST either be added to this map with a comment
	// explaining why it is exempt, or it must be added to key_claims.proto's VmProtectionKeyClaims.
	exemptions := map[string]string{
		"KeyHandle":              "KeyHandle is passed in the GetKeyClaimsRequest wrapper, not inside the VmProtectionKeyClaims body.",
		"KeyProtectionMechanism": "KeyProtectionMechanism is implicit in KeyClaims based on which oneof is populated.",
		"PubKey":                 "PubKey (PubKeyInfo) represents the generic public key in WSD, whereas KeyClaims splits this into specific KemPubKey and BindingPubKey.",
	}

	wsdType := reflect.TypeOf(api.KeyInfo{})
	claimsType := reflect.TypeOf(keymanager.KeyClaims_VmProtectionKeyClaims{})

	// We also want to check GenerateKeyResponse as it should align with KeyInfo
	genRespType := reflect.TypeOf(api.GenerateKeyResponse{})

	t.Run("KeyInfo_vs_VmProtectionKeyClaims", func(t *testing.T) {
		for i := 0; i < wsdType.NumField(); i++ {
			wsdField := wsdType.Field(i)
			fieldName := wsdField.Name

			if isProtoInternal(fieldName) {
				continue
			}

			if reason, exempt := exemptions[fieldName]; exempt {
				t.Logf("Skipping exempted field %q. Reason: %s", fieldName, reason)
				continue
			}

			claimsField, exists := claimsType.FieldByName(fieldName)
			if !exists {
				t.Errorf("Parity Violation! Field %q exists in api.KeyInfo but is missing from keymanager.VmProtectionKeyClaims. "+
					"If this is intentional, add it to the 'exemptions' map in TestProtoFieldAlignment with a justification. "+
					"Otherwise, update key_claims.proto to include this field.", fieldName)
				continue
			}

			if wsdField.Type != claimsField.Type {
				t.Errorf("Type Mismatch! Field %q is type %v in WSD api.KeyInfo, but type %v in keymanager.VmProtectionKeyClaims",
					fieldName, wsdField.Type, claimsField.Type)
			}
		}
	})

	t.Run("GenerateKeyResponse_vs_KeyInfo", func(t *testing.T) {
		// Ensure GenerateKeyResponse doesn't drift from KeyInfo either, as they represent the same key metadata
		for i := 0; i < genRespType.NumField(); i++ {
			genField := genRespType.Field(i)
			fieldName := genField.Name

			if isProtoInternal(fieldName) {
				continue
			}

			wsdField, exists := wsdType.FieldByName(fieldName)
			if !exists {
				t.Errorf("Inconsistency! Field %q exists in api.GenerateKeyResponse but is missing from api.KeyInfo", fieldName)
				continue
			}

			if genField.Type != wsdField.Type {
				t.Errorf("Type Mismatch! Field %q is type %v in GenerateKeyResponse, but type %v in KeyInfo",
					fieldName, genField.Type, wsdField.Type)
			}
		}
	})

	t.Run("KPS_GetKEMKeyResponse_vs_VmProtectionKeyClaims", func(t *testing.T) {
		kpsRespType := reflect.TypeOf(kpspb.GetKEMKeyResponse{})
		claimsExemptions := map[string]string{
			"ExpirationTime":    "ExpirationTime (double) in Claims is represented as RemainingLifespanSecs (uint64) in KPS.",
			"RemainingLifespan": "RemainingLifespan (Duration) in Claims is represented as RemainingLifespanSecs (uint64) in KPS.",
		}

		for i := 0; i < claimsType.NumField(); i++ {
			claimsField := claimsType.Field(i)
			fieldName := claimsField.Name

			if isProtoInternal(fieldName) {
				continue
			}

			if reason, exempt := claimsExemptions[fieldName]; exempt {
				t.Logf("Skipping exempted Claims field %q. Reason: %s", fieldName, reason)
				continue
			}

			kpsField, exists := kpsRespType.FieldByName(fieldName)
			if !exists {
				t.Errorf("Parity Violation! Field %q exists in keymanager.VmProtectionKeyClaims but is missing from KPS GetKEMKeyResponse. "+
					"If this is intentional, add it to 'claimsExemptions' in TestProtoFieldAlignment. "+
					"Otherwise, update KPS api.proto to include this field.", fieldName)
				continue
			}

			if claimsField.Type != kpsField.Type {
				t.Errorf("Type Mismatch! Field %q is type %v in KeyClaims, but type %v in KPS GetKEMKeyResponse",
					fieldName, claimsField.Type, kpsField.Type)
			}
		}
	})
}

func isProtoInternal(name string) bool {
	// Protobuf generated structs contain internal fields starting with lower case or XXX_
	if len(name) == 0 {
		return true
	}
	firstChar := name[0:1]
	return strings.ToLower(firstChar) == firstChar || strings.HasPrefix(name, "XXX_")
}
