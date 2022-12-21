package pubsignals

import (
	"context"
	"errors"
	"math/big"
	"testing"

	core "github.com/iden3/go-iden3-core"
	"github.com/stretchr/testify/require"
)

var (
	iid, _      = new(big.Int).SetString("24321776247489977391892714204849454424732134960326243894281082684329361408", 10)
	issuerID, _ = core.IDFromInt(iid)

	schemaHashInt, _ = big.NewInt(0).SetString("336615423900919464193075592850483704600", 10)
	coreSchema       = core.NewSchemaHashFromInt(schemaHashInt)
)

type mockMemorySchemaLoader struct {
}

func (r *mockMemorySchemaLoader) Load(_ context.Context, _ string) (schema []byte, ext string, err error) {
	return []byte(`{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "$metadata": {
    "uris": {
      "jsonLdContext": "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
      "jsonSchema": "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json/KYCCountryOfResidenceCredential-v2.json"
    },
	"serialization": {
		"valueDataSlotB": "countryCode"
	}
  },
  "@context": [
    {
      "@version": 1.1,
      "@protected": true,
      "id": "@id",
      "type": "@type",
      "KYCAgeCredential": {
        "@id": "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld#KYCAgeCredential",
        "@context": {
          "@version": 1.1,
          "@protected": true,
          "id": "@id",
          "type": "@type",
          "kyc-vocab": "https://github.com/iden3/claim-schema-vocab/blob/main/credentials/kyc.md#",
          "xsd": "http://www.w3.org/2001/XMLSchema#",
          "birthday": {
            "@id": "kyc-vocab:birthday",
            "@type": "xsd:integer"
          },
          "documentType": {
            "@id": "kyc-vocab:documentType",
            "@type": "xsd:integer"
          }
        }
      },
      "KYCCountryOfResidenceCredential": {
        "@id": "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld#KYCCountryOfResidenceCredential",
        "@context": {
          "@version": 1.1,
          "@protected": true,
          "id": "@id",
          "type": "@type",
          "kyc-vocab": "https://github.com/iden3/claim-schema-vocab/blob/main/credentials/kyc.md#",
          "xsd": "http://www.w3.org/2001/XMLSchema#",
          "countryCode": {
            "@id": "kyc-vocab:countryCode",
            "@type": "xsd:integer"
          },
          "documentType": {
            "@id": "kyc-vocab:documentType",
            "@type": "xsd:integer"
          }
        }
      }
    }
  ]
}
`), "json-ld", nil
}

func TestCheckRequest_Success(t *testing.T) {
	tests := []struct {
		name   string
		query  Query
		pubSig *CircuitOutputs
	}{
		{
			name: "Check merkalized query",
			query: Query{
				AllowedIssuers: []string{"*"},
				Req: map[string]interface{}{
					"countryCode": map[string]interface{}{
						"$nin": []interface{}{float64(800)},
					},
				},
				Context: "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
				Type:    "KYCCountryOfResidenceCredential",
			},
			pubSig: &CircuitOutputs{
				IssuerID:    &issuerID,
				ClaimSchema: coreSchema,
				ClaimPathKey: func() *big.Int {
					v, _ := big.NewInt(0).SetString("17002437119434618783545694633038537380726339994244684348913844923422470806844", 10)
					return v
				}(),
				Operator:            5,
				Value:               []*big.Int{big.NewInt(800)},
				Merklized:           1,
				IsRevocationChecked: 1,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.query.CheckRequest(context.Background(), &mockMemorySchemaLoader{}, tt.pubSig)
			require.NoError(t, err)
		})
	}
}

func TestCheckRequest_Error(t *testing.T) {
	tests := []struct {
		name   string
		query  Query
		pubSig *CircuitOutputs
		expErr error
	}{
		{
			name: "Invalid issuer",
			query: Query{
				AllowedIssuers: []string{"123"},
			},
			pubSig: &CircuitOutputs{
				IssuerID: &issuerID,
			},
			expErr: ErrUnavailableIssuer,
		},
		{
			name: "Invalid Schema ID",
			query: Query{
				AllowedIssuers: []string{issuerID.String()},
				Context:        "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
				Type:           "KYCAgeCredential",
			},
			pubSig: &CircuitOutputs{
				IssuerID:    &issuerID,
				ClaimSchema: coreSchema,
			},
			expErr: ErrSchemaID,
		},
		{
			name: "Multiply query",
			query: Query{
				AllowedIssuers: []string{issuerID.String()},
				Context:        "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
				Type:           "KYCCountryOfResidenceCredential",
				Req: map[string]interface{}{
					"req1": struct{}{},
					"req2": struct{}{},
				},
			},
			pubSig: &CircuitOutputs{
				IssuerID:    &issuerID,
				ClaimSchema: coreSchema,
			},
			expErr: errors.New("multiple requests not supported"),
		},
		{
			name: "Failed params in request",
			query: Query{
				AllowedIssuers: []string{issuerID.String()},
				Context:        "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
				Type:           "KYCCountryOfResidenceCredential",
				Req: map[string]interface{}{
					"req1": 1,
				},
			},
			pubSig: &CircuitOutputs{
				IssuerID:    &issuerID,
				ClaimSchema: coreSchema,
			},
			expErr: errors.New("failed cast type map[string]interface"),
		},
		{
			name: "Multiple predicates in one request",
			query: Query{
				AllowedIssuers: []string{issuerID.String()},
				Context:        "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
				Type:           "KYCCountryOfResidenceCredential",
				Req: map[string]interface{}{
					"countryCode": map[string]interface{}{
						"$eq":  20,
						"$nin": 21,
					},
				},
			},
			pubSig: &CircuitOutputs{
				IssuerID:    &issuerID,
				ClaimSchema: coreSchema,
			},
			expErr: errors.New("multiple predicates for one field not supported"),
		},
		{
			name: "Proof was generated for another query",
			query: Query{
				AllowedIssuers: []string{issuerID.String()},
				Context:        "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
				Type:           "KYCCountryOfResidenceCredential",
				Req: map[string]interface{}{
					"countryCode": map[string]interface{}{
						"$eq": []interface{}{float64(20)},
					},
				},
			},
			pubSig: &CircuitOutputs{
				IssuerID:    &issuerID,
				ClaimSchema: coreSchema,
				Operator:    3,
			},
			expErr: ErrRequestOperator,
		},
		{
			name: "Proof was generated for another values",
			query: Query{
				AllowedIssuers: []string{issuerID.String()},
				Context:        "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
				Type:           "KYCCountryOfResidenceCredential",
				Req: map[string]interface{}{
					"countyCode": map[string]interface{}{
						"$nin": []interface{}{float64(20)},
					},
				},
			},
			pubSig: &CircuitOutputs{
				IssuerID:    &issuerID,
				ClaimSchema: coreSchema,
				Operator:    5,
				Value:       []*big.Int{big.NewInt(40)},
			},
			expErr: ErrInvalidValues,
		},
		{
			name: "Proof was generated for another path",
			query: Query{
				AllowedIssuers: []string{issuerID.String()},
				Context:        "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
				Type:           "KYCCountryOfResidenceCredential",
				Req: map[string]interface{}{
					"documentType": map[string]interface{}{
						"$nin": []interface{}{float64(20)},
					},
				},
			},
			pubSig: &CircuitOutputs{
				IssuerID:            &issuerID,
				ClaimSchema:         coreSchema,
				ClaimPathKey:        big.NewInt(0),
				Operator:            5,
				Value:               []*big.Int{big.NewInt(20)},
				Merklized:           1,
				IsRevocationChecked: 1,
			},
			expErr: errors.New("proof was generated for another path"),
		},
		{
			name: "Different slot index",
			query: Query{
				AllowedIssuers: []string{issuerID.String()},
				Context:        "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
				Type:           "KYCCountryOfResidenceCredential",
				Req: map[string]interface{}{
					"countryCode": map[string]interface{}{
						"$nin": []interface{}{float64(20)},
					},
				},
			},
			pubSig: &CircuitOutputs{
				IssuerID:            &issuerID,
				ClaimSchema:         coreSchema,
				Operator:            5,
				Value:               []*big.Int{big.NewInt(20)},
				Merklized:           0,
				SlotIndex:           0,
				IsRevocationChecked: 1,
			},
			expErr: errors.New("different slot index for claim"),
		},
		{
			name: "Check revocation is required",
			query: Query{
				AllowedIssuers: []string{issuerID.String()},
				Context:        "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
				Type:           "KYCCountryOfResidenceCredential",
				Req: map[string]interface{}{
					"countryCode": map[string]interface{}{
						"$nin": []interface{}{float64(20)},
					},
				},
				SkipClaimRevocationCheck: false,
			},
			pubSig: &CircuitOutputs{
				IssuerID:            &issuerID,
				ClaimSchema:         coreSchema,
				Operator:            5,
				Value:               []*big.Int{big.NewInt(20)},
				Merklized:           0,
				SlotIndex:           0,
				IsRevocationChecked: 0,
			},
			expErr: errors.New("check revocation is required"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.query.CheckRequest(context.Background(), &mockMemorySchemaLoader{}, tt.pubSig)
			require.EqualError(t, err, tt.expErr.Error())
		})
	}
}
