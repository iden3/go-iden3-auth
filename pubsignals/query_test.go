package pubsignals

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/iden3/go-circuits/v2"
	core "github.com/iden3/go-iden3-core/v2"
	"github.com/iden3/go-schema-processor/v2/utils"
	"github.com/piprate/json-gold/ld"
	"github.com/stretchr/testify/require"
)

var (
	issuerDID         = "did:polygonid:polygon:mumbai:2qHSHBGWGJ68AosMKcLCTp8FYdVrtYE6MtNHhq8xpK"
	iid, _            = new(big.Int).SetString("22638457188543025296541325416907897762715008870723718557276875842936181250", 10)
	issuerID, _       = core.IDFromInt(iid)
	bigIntTrueHash, _ = big.NewInt(0).SetString("18586133768512220936620570745912940619677854269274689475585506675881198879027", 10)
)

type mockJSONLDSchemaLoader struct {
	schemas map[string]string
	seen    map[string]bool
}

func (r *mockJSONLDSchemaLoader) LoadDocument(u string) (*ld.RemoteDocument, error) {
	if body, ok := r.schemas[u]; ok {
		if r.seen == nil {
			r.seen = make(map[string]bool)
		}
		r.seen[u] = true
		var doc = ld.RemoteDocument{DocumentURL: u}
		err := json.Unmarshal([]byte(body), &doc.Document)
		return &doc, err
	}
	return nil, fmt.Errorf("schema not found: %v", u)
}

func (r *mockJSONLDSchemaLoader) assert(t testing.TB) {
	for url := range r.schemas {
		require.True(t, r.seen[url], "schema not loaded: %v", url)
	}
}

var vp = []byte(`{
	"@context": [
		"https://www.w3.org/2018/credentials/v1"
	],
	"@type": "VerifiablePresentation",
	"verifiableCredential": {
		"@context": [
			"https://www.w3.org/2018/credentials/v1",
			"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld"
		],
		"@type": ["VerifiableCredential","KYCCountryOfResidenceCredential"],
		"credentialSubject": {
			"type": "KYCCountryOfResidenceCredential",
			"countryCode": 800
		}
	}
}`)

var vpEmployee = []byte(`{
	"@type": "VerifiablePresentation",
	"@context": [
		"https://www.w3.org/2018/credentials/v1"
	],
	"verifiableCredential": {
		"@context": [
			"https://www.w3.org/2018/credentials/v1",
			"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v101.json-ld"
		],
		"@type": [
			"VerifiableCredential",
			"KYCEmployee"
		],
		"credentialSubject": {
			"@type": "KYCEmployee",
			"position": "SSI Consultant"
		}
	}
}`)

func TestCheckRequest_Success(t *testing.T) {
	now := time.Now().Unix()
	tests := []struct {
		name   string
		query  Query
		pubSig *CircuitOutputs
		vp     json.RawMessage
		loader *mockJSONLDSchemaLoader
	}{
		{
			name: "Check merklized query",
			query: Query{
				AllowedIssuers: []string{"*"},
				CredentialSubject: map[string]interface{}{
					"countryCode": map[string]interface{}{
						"$nin": []interface{}{float64(800)},
					},
				},
				Context: "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
				Type:    "KYCCountryOfResidenceCredential",
			},
			pubSig: &CircuitOutputs{
				IssuerID:    &issuerID,
				ClaimSchema: utils.CreateSchemaHash([]byte("https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld#KYCCountryOfResidenceCredential")),
				ClaimPathKey: func() *big.Int {
					v, _ := big.NewInt(0).SetString("17002437119434618783545694633038537380726339994244684348913844923422470806844", 10)
					return v
				}(),
				Operator: 5,
				Value: func() []*big.Int {
					v, _ := circuits.PrepareCircuitArrayValues([]*big.Int{big.NewInt(800)}, 64)
					return v
				}(),
				Merklized:           1,
				IsRevocationChecked: 1,
				Timestamp:           now,
			},
			loader: &mockJSONLDSchemaLoader{
				schemas: map[string]string{
					"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld": loadSchema("kyc-v3.json-ld"),
				},
			},
		},
		{
			name: "Selective disclosure",
			query: Query{
				AllowedIssuers: []string{"*"},
				CredentialSubject: map[string]interface{}{
					"countryCode": map[string]interface{}{},
				},
				Context: "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
				Type:    "KYCCountryOfResidenceCredential",
			},
			pubSig: &CircuitOutputs{
				IssuerID:    &issuerID,
				ClaimSchema: utils.CreateSchemaHash([]byte("https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld#KYCCountryOfResidenceCredential")),
				ClaimPathKey: func() *big.Int {
					v, _ := big.NewInt(0).SetString("17002437119434618783545694633038537380726339994244684348913844923422470806844", 10)
					return v
				}(),
				Operator: 1,
				Value: func() []*big.Int {
					v, _ := circuits.PrepareCircuitArrayValues([]*big.Int{big.NewInt(800)}, 64)
					return v
				}(),
				Merklized:           1,
				IsRevocationChecked: 1,
				Timestamp:           now,
			},
			vp: vp,
			loader: &mockJSONLDSchemaLoader{
				schemas: map[string]string{
					"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld": loadSchema("kyc-v3.json-ld"),
					"https://www.w3.org/2018/credentials/v1":                                                         loadSchema("credentials-v1.json-ld"),
				},
			},
		},
		{
			name: "Query with boolean type",
			query: Query{
				AllowedIssuers: []string{"*"},
				CredentialSubject: map[string]interface{}{
					"ZKPexperiance": map[string]interface{}{
						"$eq": true,
					},
				},
				Context: "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v101.json-ld",
				Type:    "KYCEmployee",
			},
			pubSig: &CircuitOutputs{
				IssuerID:    &issuerID,
				ClaimSchema: utils.CreateSchemaHash([]byte("https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v101.json-ld#KYCEmployee")),
				ClaimPathKey: func() *big.Int {
					v, _ := big.NewInt(0).SetString("1944808975288007371356450257872165609440470546066507760733183342797918372827", 10)
					return v
				}(),
				Operator: 1,
				Value: func() []*big.Int {
					v, _ := circuits.PrepareCircuitArrayValues([]*big.Int{bigIntTrueHash}, 64)
					return v
				}(),
				Merklized:           1,
				IsRevocationChecked: 1,
				Timestamp:           now,
			},
			loader: &mockJSONLDSchemaLoader{
				schemas: map[string]string{
					"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v101.json-ld": loadSchema("kyc-v101.json-ld"),
				},
			},
		},
		{
			name: "Selective disclosure with xsd:string type",
			query: Query{
				AllowedIssuers: []string{"*"},
				CredentialSubject: map[string]interface{}{
					"position": map[string]interface{}{},
				},
				Context: "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v101.json-ld",
				Type:    "KYCEmployee",
			},
			pubSig: &CircuitOutputs{
				IssuerID:    &issuerID,
				ClaimSchema: utils.CreateSchemaHash([]byte("https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v101.json-ld#KYCEmployee")),
				ClaimPathKey: func() *big.Int {
					v, _ := big.NewInt(0).SetString("15406634529806189041952040954758558497189093183268091368437514469450172572054", 10)
					return v
				}(),
				Operator: 1,
				Value: func() []*big.Int {
					v, _ := big.NewInt(0).SetString("957410455271905675920624030785024750144198809104092676617070098470852489834", 10)
					r, _ := circuits.PrepareCircuitArrayValues([]*big.Int{v}, 64)
					return r
				}(),
				Merklized:           1,
				IsRevocationChecked: 1,
				Timestamp:           now,
			},
			vp: vpEmployee,
			loader: &mockJSONLDSchemaLoader{
				schemas: map[string]string{
					"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v101.json-ld": loadSchema("kyc-v101.json-ld"),
					"https://www.w3.org/2018/credentials/v1":                                                           loadSchema("credentials-v1.json-ld"),
				},
			},
		},
		{
			name: "EQ operator for xsd:string type",
			query: Query{
				AllowedIssuers: []string{"*"},
				CredentialSubject: map[string]interface{}{
					"position": map[string]interface{}{
						"$eq": "Software Engineer",
					},
				},
				Context: "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v101.json-ld",
				Type:    "KYCEmployee",
			},
			pubSig: &CircuitOutputs{
				IssuerID:    &issuerID,
				ClaimSchema: utils.CreateSchemaHash([]byte("https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v101.json-ld#KYCEmployee")),
				ClaimPathKey: func() *big.Int {
					v, _ := big.NewInt(0).SetString("15406634529806189041952040954758558497189093183268091368437514469450172572054", 10)
					return v
				}(),
				Operator: 1,
				Value: func() []*big.Int {
					v, _ := big.NewInt(0).SetString("7481731651336040098616464366227645531920423822088928207225802836605991806542", 10)
					r, _ := circuits.PrepareCircuitArrayValues([]*big.Int{v}, 64)
					return r
				}(),
				Merklized:           1,
				IsRevocationChecked: 1,
				Timestamp:           now,
			},
			vp: vpEmployee,
			loader: &mockJSONLDSchemaLoader{
				schemas: map[string]string{
					"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v101.json-ld": loadSchema("kyc-v101.json-ld"),
				},
			},
		},
		{
			name: "Non merklized claim",
			query: Query{
				AllowedIssuers: []string{"*"},
				CredentialSubject: map[string]interface{}{
					"birthday": map[string]interface{}{
						"$eq": "19960424",
					},
				},
				Context: "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-nonmerklized.jsonld",
				Type:    "KYCAgeCredential",
			},
			pubSig: &CircuitOutputs{
				IssuerID:    &issuerID,
				ClaimSchema: utils.CreateSchemaHash([]byte("https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-nonmerklized.jsonld#KYCAgeCredential")),
				Operator:    1,
				Value: func() []*big.Int {
					v, _ := circuits.PrepareCircuitArrayValues([]*big.Int{big.NewInt(19960424)}, 64)
					return v
				}(),
				Merklized:           0,
				SlotIndex:           2,
				IsRevocationChecked: 1,
				Timestamp:           now,
			},
			loader: &mockJSONLDSchemaLoader{
				schemas: map[string]string{
					"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-nonmerklized.jsonld": loadSchema("kyc-nonmerklized.jsonld"),
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.query.Check(context.Background(), tt.loader, tt.pubSig, tt.vp, circuits.AtomicQuerySigV2CircuitID)
			require.NoError(t, err)
			tt.loader.assert(t)
		})
	}
}

func TestCheckRequest_SelectiveDisclosure_Error(t *testing.T) {
	now := time.Now().Unix()
	durationMin, _ := time.ParseDuration("-1m")
	dayAndMinuteAgo := time.Now().AddDate(0, 0, -1).Add(durationMin).Unix()
	tests := []struct {
		name   string
		query  Query
		pubSig *CircuitOutputs
		vp     json.RawMessage
		expErr error
		loader *mockJSONLDSchemaLoader
	}{
		{
			name: "Generated proof is outdated",
			query: Query{
				AllowedIssuers: []string{"*"},
				CredentialSubject: map[string]interface{}{
					"countryCode": map[string]interface{}{
						"$nin": []interface{}{float64(800)},
					},
				},
				Context: "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
				Type:    "KYCCountryOfResidenceCredential",
			},
			pubSig: &CircuitOutputs{
				IssuerID:    &issuerID,
				ClaimSchema: utils.CreateSchemaHash([]byte("https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld#KYCCountryOfResidenceCredential")),
				ClaimPathKey: func() *big.Int {
					v, _ := big.NewInt(0).SetString("17002437119434618783545694633038537380726339994244684348913844923422470806844", 10)
					return v
				}(),
				Operator: 5,
				Value: func() []*big.Int {
					v, _ := circuits.PrepareCircuitArrayValues([]*big.Int{big.NewInt(800)}, 64)
					return v
				}(),
				Merklized:           1,
				IsRevocationChecked: 1,
				Timestamp:           dayAndMinuteAgo,
			},
			expErr: errors.New("generated proof is outdated"),
			loader: &mockJSONLDSchemaLoader{
				schemas: map[string]string{
					"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld": loadSchema("kyc-v3.json-ld"),
				},
			},
		},
		{
			name: "Empty disclosure value for disclosure request",
			query: Query{
				AllowedIssuers: []string{"*"},
				CredentialSubject: map[string]interface{}{
					"countryCode": map[string]interface{}{},
				},
				Context: "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
				Type:    "KYCCountryOfResidenceCredential",
			},
			vp: nil,
			pubSig: &CircuitOutputs{
				IssuerID:    &issuerID,
				ClaimSchema: utils.CreateSchemaHash([]byte("https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld#KYCCountryOfResidenceCredential")),
				ClaimPathKey: func() *big.Int {
					v, _ := big.NewInt(0).SetString("17002437119434618783545694633038537380726339994244684348913844923422470806844", 10)
					return v
				}(),
				Operator: 1,
				Value: func() []*big.Int {
					v, _ := circuits.PrepareCircuitArrayValues([]*big.Int{big.NewInt(800)}, 64)
					return v
				}(),
				Merklized:           1,
				IsRevocationChecked: 1,
				Timestamp:           now,
			},
			expErr: errors.New("selective disclosure value is missed"),
			loader: &mockJSONLDSchemaLoader{
				schemas: map[string]string{
					"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld": loadSchema("kyc-v3.json-ld"),
				},
			},
		},
		{
			name: "Not EQ operation for disclosure request",
			query: Query{
				AllowedIssuers: []string{"*"},
				CredentialSubject: map[string]interface{}{
					"countryCode": map[string]interface{}{},
				},
				Context: "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
				Type:    "KYCCountryOfResidenceCredential",
			},
			vp: vp,
			pubSig: &CircuitOutputs{
				IssuerID:    &issuerID,
				ClaimSchema: utils.CreateSchemaHash([]byte("https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld#KYCCountryOfResidenceCredential")),
				ClaimPathKey: func() *big.Int {
					v, _ := big.NewInt(0).SetString("17002437119434618783545694633038537380726339994244684348913844923422470806844", 10)
					return v
				}(),
				Operator: 5,
				Value: func() []*big.Int {
					v, _ := circuits.PrepareCircuitArrayValues([]*big.Int{big.NewInt(800)}, 64)
					return v
				}(),
				Merklized:           1,
				IsRevocationChecked: 1,
				Timestamp:           now,
			},
			expErr: errors.New("selective disclosure available only for equal operation"),
			loader: &mockJSONLDSchemaLoader{
				schemas: map[string]string{
					"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld": loadSchema("kyc-v3.json-ld"),
					"https://www.w3.org/2018/credentials/v1":                                                         loadSchema("credentials-v1.json-ld"),
				},
			},
		},
		{
			name: "Not array of values for disclosure request",
			query: Query{
				AllowedIssuers: []string{"*"},
				CredentialSubject: map[string]interface{}{
					"countryCode": map[string]interface{}{},
				},
				Context: "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
				Type:    "KYCCountryOfResidenceCredential",
			},
			vp: vp,
			pubSig: &CircuitOutputs{
				IssuerID:    &issuerID,
				ClaimSchema: utils.CreateSchemaHash([]byte("https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld#KYCCountryOfResidenceCredential")),
				ClaimPathKey: func() *big.Int {
					v, _ := big.NewInt(0).SetString("17002437119434618783545694633038537380726339994244684348913844923422470806844", 10)
					return v
				}(),
				Operator: 1,
				Value: func() []*big.Int {
					v, _ := circuits.PrepareCircuitArrayValues([]*big.Int{big.NewInt(800), big.NewInt(801)}, 64)
					return v
				}(),
				Merklized:           1,
				IsRevocationChecked: 1,
				Timestamp:           now,
			},
			expErr: errors.New("selective disclosure not available for array of values"),
			loader: &mockJSONLDSchemaLoader{
				schemas: map[string]string{
					"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld": loadSchema("kyc-v3.json-ld"),
					"https://www.w3.org/2018/credentials/v1":                                                         loadSchema("credentials-v1.json-ld"),
				},
			},
		},
		{
			name: "Proof was generated for another disclosure value",
			query: Query{
				AllowedIssuers: []string{"*"},
				CredentialSubject: map[string]interface{}{
					"countryCode": map[string]interface{}{},
				},
				Context: "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
				Type:    "KYCCountryOfResidenceCredential",
			},
			vp: vp,
			pubSig: &CircuitOutputs{
				IssuerID:    &issuerID,
				ClaimSchema: utils.CreateSchemaHash([]byte("https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld#KYCCountryOfResidenceCredential")),
				ClaimPathKey: func() *big.Int {
					v, _ := big.NewInt(0).SetString("17002437119434618783545694633038537380726339994244684348913844923422470806844", 10)
					return v
				}(),
				Operator: 1,
				Value: func() []*big.Int {
					v, _ := circuits.PrepareCircuitArrayValues([]*big.Int{big.NewInt(1)}, 64)
					return v
				}(),
				Merklized:           1,
				IsRevocationChecked: 1,
				Timestamp:           now,
			},
			expErr: errors.New("different value between proof and disclosure value"),
			loader: &mockJSONLDSchemaLoader{
				schemas: map[string]string{
					"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld": loadSchema("kyc-v3.json-ld"),
					"https://www.w3.org/2018/credentials/v1":                                                         loadSchema("credentials-v1.json-ld"),
				},
			},
		},
		{
			name: "Different key between proof and disclosure response",
			query: Query{
				AllowedIssuers: []string{"*"},
				CredentialSubject: map[string]interface{}{
					"documentType": map[string]interface{}{},
				},
				Context: "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
				Type:    "KYCCountryOfResidenceCredential",
			},
			vp: vp,
			pubSig: &CircuitOutputs{
				IssuerID:    &issuerID,
				ClaimSchema: utils.CreateSchemaHash([]byte("https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld#KYCCountryOfResidenceCredential")),
				ClaimPathKey: func() *big.Int {
					v, _ := big.NewInt(0).SetString("17002437119434618783545694633038537380726339994244684348913844923422470806844", 10)
					return v
				}(),
				Operator: 1,
				Value: func() []*big.Int {
					v, _ := circuits.PrepareCircuitArrayValues([]*big.Int{big.NewInt(800)}, 64)
					return v
				}(),
				Merklized:           1,
				IsRevocationChecked: 1,
				Timestamp:           now,
			},
			expErr: errors.New("path '[https://www.w3.org/2018/credentials#verifiableCredential https://www.w3.org/2018/credentials#credentialSubject https://github.com/iden3/claim-schema-vocab/blob/main/credentials/kyc.md#documentType]' doesn't exist in document"),
			loader: &mockJSONLDSchemaLoader{
				schemas: map[string]string{
					"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld": loadSchema("kyc-v3.json-ld"),
					"https://www.w3.org/2018/credentials/v1":                                                         loadSchema("credentials-v1.json-ld"),
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.query.Check(context.Background(), tt.loader, tt.pubSig, tt.vp, circuits.AtomicQuerySigV2CircuitID)
			require.EqualError(t, err, tt.expErr.Error())
			tt.loader.assert(t)
		})
	}
}

func TestCheckRequest_Error(t *testing.T) {
	now := time.Now().Unix()
	tests := []struct {
		name   string
		query  Query
		pubSig *CircuitOutputs
		expErr error
		loader *mockJSONLDSchemaLoader
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
			loader: &mockJSONLDSchemaLoader{},
		},
		{
			name: "Invalid Schema ID",
			query: Query{
				AllowedIssuers: []string{issuerDID},
				Context:        "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
				Type:           "KYCAgeCredential",
			},
			pubSig: &CircuitOutputs{
				IssuerID:    &issuerID,
				ClaimSchema: utils.CreateSchemaHash([]byte("https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld#KYCCountryOfResidenceCredential")),
				Timestamp:   now,
			},
			expErr: ErrSchemaID,
			loader: &mockJSONLDSchemaLoader{
				schemas: map[string]string{
					"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld": loadSchema("kyc-v3.json-ld"),
				},
			},
		},
		{
			name: "Multiply query",
			query: Query{
				AllowedIssuers: []string{issuerDID},
				Context:        "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
				Type:           "KYCCountryOfResidenceCredential",
				CredentialSubject: map[string]interface{}{
					"countryCode": map[string]interface{}{
						"$nin": []interface{}{float64(800)},
					},
					"documentType": map[string]interface{}{
						"$eq": []interface{}{float64(1)},
					},
				},
			},
			pubSig: &CircuitOutputs{
				IssuerID:            &issuerID,
				ClaimSchema:         utils.CreateSchemaHash([]byte("https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld#KYCCountryOfResidenceCredential")),
				Timestamp:           now,
				IsRevocationChecked: 1,
			},
			expErr: errors.New("multiple requests not supported"),
			loader: &mockJSONLDSchemaLoader{
				schemas: map[string]string{
					"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld": loadSchema("kyc-v3.json-ld"),
				},
			},
		},
		{
			name: "Failed params in request",
			query: Query{
				AllowedIssuers: []string{issuerDID},
				Context:        "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
				Type:           "KYCCountryOfResidenceCredential",
				CredentialSubject: map[string]interface{}{
					"req1": 1,
				},
			},
			pubSig: &CircuitOutputs{
				IssuerID:            &issuerID,
				ClaimSchema:         utils.CreateSchemaHash([]byte("https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld#KYCCountryOfResidenceCredential")),
				Timestamp:           now,
				IsRevocationChecked: 1,
			},
			expErr: errors.New("failed cast type map[string]interface"),
			loader: &mockJSONLDSchemaLoader{
				schemas: map[string]string{
					"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld": loadSchema("kyc-v3.json-ld"),
				},
			},
		},
		{
			name: "Multiple predicates in one request",
			query: Query{
				AllowedIssuers: []string{issuerDID},
				Context:        "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
				Type:           "KYCCountryOfResidenceCredential",
				CredentialSubject: map[string]interface{}{
					"countryCode": map[string]interface{}{
						"$eq":  20,
						"$nin": 21,
					},
				},
			},
			pubSig: &CircuitOutputs{
				IssuerID:            &issuerID,
				ClaimSchema:         utils.CreateSchemaHash([]byte("https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld#KYCCountryOfResidenceCredential")),
				Timestamp:           now,
				IsRevocationChecked: 1,
			},
			expErr: errors.New("multiple requests not supported"),
			loader: &mockJSONLDSchemaLoader{
				schemas: map[string]string{
					"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld": loadSchema("kyc-v3.json-ld"),
				},
			},
		},
		{
			name: "Proof was generated for another query operator",
			query: Query{
				AllowedIssuers: []string{issuerDID},
				Context:        "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
				Type:           "KYCCountryOfResidenceCredential",
				CredentialSubject: map[string]interface{}{
					"countryCode": map[string]interface{}{
						"$eq": []interface{}{float64(20)},
					},
				},
			},
			pubSig: &CircuitOutputs{
				IssuerID:            &issuerID,
				ClaimSchema:         utils.CreateSchemaHash([]byte("https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld#KYCCountryOfResidenceCredential")),
				Operator:            3,
				Timestamp:           now,
				IsRevocationChecked: 1,
			},
			expErr: ErrRequestOperator,
			loader: &mockJSONLDSchemaLoader{
				schemas: map[string]string{
					"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld": loadSchema("kyc-v3.json-ld"),
				},
			},
		},
		{
			name: "Proof was generated for another values",
			query: Query{
				AllowedIssuers: []string{issuerDID},
				Context:        "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
				Type:           "KYCCountryOfResidenceCredential",
				CredentialSubject: map[string]interface{}{
					"countryCode": map[string]interface{}{
						"$nin": []interface{}{float64(20)},
					},
				},
			},
			pubSig: &CircuitOutputs{
				IssuerID:            &issuerID,
				ClaimSchema:         utils.CreateSchemaHash([]byte("https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld#KYCCountryOfResidenceCredential")),
				Operator:            5,
				Value:               []*big.Int{big.NewInt(40)},
				Timestamp:           now,
				IsRevocationChecked: 1,
			},
			expErr: ErrInvalidValues,
			loader: &mockJSONLDSchemaLoader{
				schemas: map[string]string{
					"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld": loadSchema("kyc-v3.json-ld"),
				},
			},
		},
		{
			name: "Proof was generated for another path",
			query: Query{
				AllowedIssuers: []string{issuerDID},
				Context:        "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
				Type:           "KYCCountryOfResidenceCredential",
				CredentialSubject: map[string]interface{}{
					"documentType": map[string]interface{}{
						"$nin": []interface{}{float64(20)},
					},
				},
			},
			pubSig: &CircuitOutputs{
				IssuerID:     &issuerID,
				ClaimSchema:  utils.CreateSchemaHash([]byte("https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld#KYCCountryOfResidenceCredential")),
				ClaimPathKey: big.NewInt(0),
				Operator:     5,
				Value: func() []*big.Int {
					v, _ := circuits.PrepareCircuitArrayValues([]*big.Int{big.NewInt(20)}, 64)
					return v
				}(),
				Merklized:           1,
				IsRevocationChecked: 1,
				Timestamp:           now,
			},
			expErr: errors.New("proof was generated for another path"),
			loader: &mockJSONLDSchemaLoader{
				schemas: map[string]string{
					"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld": loadSchema("kyc-v3.json-ld"),
				},
			},
		},
		{
			name: "Check revocation is required",
			query: Query{
				AllowedIssuers: []string{issuerDID},
				Context:        "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
				Type:           "KYCCountryOfResidenceCredential",
				CredentialSubject: map[string]interface{}{
					"countryCode": map[string]interface{}{
						"$nin": []interface{}{float64(20)},
					},
				},
				SkipClaimRevocationCheck: false,
			},
			pubSig: &CircuitOutputs{
				IssuerID:    &issuerID,
				ClaimSchema: utils.CreateSchemaHash([]byte("https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld#KYCCountryOfResidenceCredential")),
				Operator:    5,
				Value: func() []*big.Int {
					v, _ := circuits.PrepareCircuitArrayValues([]*big.Int{big.NewInt(20)}, 64)
					return v
				}(),
				Merklized:           0,
				SlotIndex:           0,
				IsRevocationChecked: 0,
				Timestamp:           now,
			},
			expErr: errors.New("check revocation is required"),
			loader: &mockJSONLDSchemaLoader{
				schemas: map[string]string{
					"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld": loadSchema("kyc-v3.json-ld"),
				},
			},
		},
		{
			name: "Unsupported lt operator for xsd:boolean",
			query: Query{
				AllowedIssuers: []string{issuerDID},
				Context:        "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v101.json-ld",
				Type:           "KYCEmployee",
				CredentialSubject: map[string]interface{}{
					"ZKPexperiance": map[string]interface{}{
						"$lt": 20,
					},
				},
				SkipClaimRevocationCheck: false,
			},
			pubSig: &CircuitOutputs{
				IssuerID:            &issuerID,
				ClaimSchema:         utils.CreateSchemaHash([]byte("https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v101.json-ld#KYCEmployee")),
				Operator:            2,
				Value:               []*big.Int{big.NewInt(20)},
				Merklized:           0,
				SlotIndex:           0,
				IsRevocationChecked: 1,
				Timestamp:           now,
			},
			expErr: errors.New("invalid operation '$lt' for field type 'http://www.w3.org/2001/XMLSchema#boolean'"),
			loader: &mockJSONLDSchemaLoader{
				schemas: map[string]string{
					"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v101.json-ld": loadSchema("kyc-v101.json-ld"),
				},
			},
		},
		{
			name: "Negative value in request",
			query: Query{
				AllowedIssuers: []string{issuerDID},
				Context:        "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v101.json-ld",
				Type:           "KYCEmployee",
				CredentialSubject: map[string]interface{}{
					"documentType": map[string]interface{}{
						"$eq": -1,
					},
				},
				SkipClaimRevocationCheck: false,
			},
			pubSig: &CircuitOutputs{
				IssuerID:    &issuerID,
				ClaimSchema: utils.CreateSchemaHash([]byte("https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v101.json-ld#KYCEmployee")),
				Operator:    1,
				Value: func() []*big.Int {
					v, _ := circuits.PrepareCircuitArrayValues([]*big.Int{big.NewInt(-1)}, 64)
					return v
				}(),
				Merklized:           0,
				SlotIndex:           0,
				IsRevocationChecked: 1,
				Timestamp:           now,
			},
			expErr: ErrNegativeValue,
			loader: &mockJSONLDSchemaLoader{
				schemas: map[string]string{
					"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v101.json-ld": loadSchema("kyc-v101.json-ld"),
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.query.Check(context.Background(), tt.loader, tt.pubSig, nil, circuits.AtomicQuerySigV2CircuitID)
			require.EqualError(t, err, tt.expErr.Error())
			tt.loader.assert(t)
		})
	}
}

func TestVerifyQuery_Success(t *testing.T) {
	tests := []struct {
		name   string
		query  Query
		pubSig *CircuitOutputs
	}{
		{
			name: "Issuer DID is valid ID from public signals",
			query: Query{
				AllowedIssuers: []string{"did:polygonid:polygon:mumbai:2qHSHBGWGJ68AosMKcLCTp8FYdVrtYE6MtNHhq8xpK"},
			},
			pubSig: &CircuitOutputs{
				IssuerID: func() *core.ID {
					i, _ := big.NewInt(0).SetString("22638457188543025296541325416907897762715008870723718557276875842936181250", 10)
					userID, _ := core.IDFromInt(i)
					return &userID
				}(),
			},
		},
		{
			name: "All issuers are allowed",
			query: Query{
				AllowedIssuers: []string{"*"},
			},
			pubSig: &CircuitOutputs{
				IssuerID: func() *core.ID {
					i, _ := big.NewInt(0).SetString("22638457188543025296541325416907897762715008870723718557276875842936181250", 10)
					userID, _ := core.IDFromInt(i)
					return &userID
				}(),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.query.verifyIssuer(tt.pubSig)
			require.NoError(t, err)
		})
	}
}

func TestVerifyQuery_Error(t *testing.T) {
	tests := []struct {
		name   string
		query  Query
		pubSig *CircuitOutputs
		err    error
	}{
		{
			name: "Invalid issuer in public signals",
			query: Query{
				AllowedIssuers: []string{"did:polygonid:polygon:mumbai:2qHSHBGWGJ68AosMKcLCTp8FYdVrtYE6MtNHhq8xpK"},
			},
			pubSig: &CircuitOutputs{
				IssuerID: func() *core.ID {
					i, _ := big.NewInt(0).SetString("42", 10)
					userID, _ := core.IDFromInt(i)
					return &userID
				}(),
			},
		},
		{
			name: "Issuer not found",
			query: Query{
				AllowedIssuers: []string{
					"did:polygonid:polygon:mumbai:2qMe71smt9D591WQdKvkbJBSQfEUQXtvyPmzoCqDd7",
					"did:polygonid:polygon:mumbai:2qPvUBjKWgqADsAr2diJabs1NkqNJii482E2y1ZciQ",
				},
			},
			pubSig: &CircuitOutputs{
				IssuerID: func() *core.ID {
					i, _ := big.NewInt(0).SetString("22638457188543025296541325416907897762715008870723718557276875842936181250", 10)
					userID, _ := core.IDFromInt(i)
					return &userID
				}(),
			},
			err: ErrUnavailableIssuer,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.query.verifyIssuer(tt.pubSig)
			fmt.Println("err", err)
			require.Error(t, err)
			if tt.err != nil {
				require.ErrorIs(t, err, tt.err)
			}
		})
	}
}

func loadSchema(name string) string {
	bs, err := os.ReadFile("../testdata/" + name)
	if err != nil {
		panic(err)
	}
	return string(bs)
}
