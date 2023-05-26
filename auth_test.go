package auth

import (
	"context"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/google/uuid"
	"github.com/iden3/go-circuits"
	"github.com/iden3/go-iden3-auth/loaders"
	"github.com/iden3/go-iden3-auth/pubsignals"
	"github.com/iden3/go-iden3-auth/state"
	"github.com/iden3/go-rapidsnark/types"
	"github.com/iden3/go-schema-processor/verifiable"
	"github.com/iden3/iden3comm"
	"github.com/iden3/iden3comm/packers"
	"github.com/iden3/iden3comm/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	// we have multiimport since two different libraries use the same package
	// with different versions
	// Same issue https://github.com/flashbots/mev-boost-relay/pull/227/files
	_ "github.com/btcsuite/btcd/btcutil"
)

var verificationKeyloader = &loaders.FSKeyLoader{Dir: "./testdata"}

const kycV2Schema = `{
  "@context": [
    {
      "@version": 1.1,
      "@protected": true,
      "id": "@id",
      "type": "@type",
      "KYCAgeCredential": {
        "@id": "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v2.json-ld#KYCAgeCredential",
        "@context": {
          "@version": 1.1,
          "@protected": true,
          "id": "@id",
          "type": "@type",
          "kyc-vocab": "https://github.com/iden3/claim-schema-vocab/blob/main/credentials/kyc.md#",
          "serialization": "https://github.com/iden3/claim-schema-vocab/blob/main/credentials/serialization.md#",
          "birthday": {
            "@id": "kyc-vocab:birthday",
            "@type": "serialization:IndexDataSlotA"
          },
          "documentType": {
            "@id": "kyc-vocab:documentType",
            "@type": "serialization:IndexDataSlotB"
          }
        }
      },
      "KYCCountryOfResidenceCredential": {
        "@id": "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v2.json-ld#KYCCountryOfResidenceCredential",
        "@context": {
          "@version": 1.1,
          "@protected": true,
          "id": "@id",
          "type": "@type",
          "kyc-vocab": "https://github.com/iden3/claim-schema-vocab/blob/main/credentials/kyc.md#",
          "serialization": "https://github.com/iden3/claim-schema-vocab/blob/main/credentials/serialization.md#",
          "countryCode": {
            "@id": "kyc-vocab:countryCode",
            "@type": "serialization:IndexDataSlotA"
          },
          "documentType": {
            "@id": "kyc-vocab:documentType",
            "@type": "serialization:IndexDataSlotB"
          }
        }
      }
    }
  ]
}`

const kycV3Schema = `{
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
}`

const kycV4Schema = `{
  "@context": [
    {
      "@version": 1.1,
      "@protected": true,
      "id": "@id",
      "type": "@type",
      "KYCAgeCredential": {
        "@id": "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v4.jsonld#KYCAgeCredential",
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
        "@id": "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v4.jsonld#KYCCountryOfResidenceCredential",
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
}`

const kycV101Schema = `{
  "@context": [
    {
      "@version": 1.1,
      "@protected": true,
      "id": "@id",
      "type": "@type",
      "KYCAgeCredential": {
        "@id": "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v101.json-ld#KYCAgeCredential",
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
        "@id": "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v101.json-ld#KYCCountryOfResidenceCredential",
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
      },
      "KYCEmployee": {
        "@id": "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v101.json-ld#KYCEmployee",
        "@context": {
          "@version": 1.1,
          "@protected": true,
          "id": "@id",
          "type": "@type",
          "kyc-vocab": "https://github.com/iden3/claim-schema-vocab/blob/main/credentials/kyc.md#",
          "xsd": "http://www.w3.org/2001/XMLSchema#",
          "documentType": {
            "@id": "kyc-vocab:documentType",
            "@type": "xsd:integer"
          },
          "ZKPexperiance": {
            "@id": "kyc-vocab:hasZKPexperiance",
            "@type": "xsd:boolean"
          },
          "hireDate": {
            "@id": "kyc-vocab:hireDate",
            "@type": "xsd:dateTime"
          },
          "position": {
            "@id": "kyc-vocab:position",
            "@type": "xsd:string"
          },
          "salary": {
            "@id": "kyc-vocab:salary",
            "@type": "xsd:double"
          }
        }
      }
    }
  ]
}`

type mockJSONLDSchemaLoader struct {
	schema string
}

func (r *mockJSONLDSchemaLoader) Load(_ context.Context, _ string) (schema []byte, ext string, err error) {
	return []byte(r.schema), "json-ld", nil
}

const exampleDidDoc = `{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/suites/secp256k1recovery-2020/v2"],"id":"did:example:123","verificationMethod":[{"id":"did:example:123#vm-1","controller":"did:example:123","type":"EcdsaSecp256k1VerificationKey2019","publicKeyJwk":{"crv":"secp256k1","kid":"did:iden3:polygon:mumbai:x4jcHP4XHTK3vX58AHZPyHE8kYjneyE6FZRfz7K29","kty":"EC","x":"YEwwxb2s2kjvKodwoW3II8JhcvYk-51hD74Kkq63syc=","y":"fCIyEltvzDs0JZnL25-YyyDgLrbZTw9y3lM2BLDhQbU="}}],"authentication":["did:example:123#vm-1"]}`

var didResolverHandler = packers.DIDResolverHandlerFunc(func(did string) (*verifiable.DIDDocument, error) {
	didDoc := &verifiable.DIDDocument{}

	err := json.Unmarshal([]byte(exampleDidDoc), didDoc)

	if err != nil {
		panic(err)
	}

	return didDoc, nil
})

/*
mock for state resolver
*/
var stateResolvers = map[string]pubsignals.StateResolver{
	"polygon:mumbai": &mockStateResolver{},
}

type mockStateResolver struct {
}

func (r *mockStateResolver) Resolve(_ context.Context, _, _ *big.Int) (*state.ResolvedState, error) {
	return &state.ResolvedState{Latest: true, Genesis: false, TransitionTimestamp: 0}, nil
}

func (r *mockStateResolver) ResolveGlobalRoot(_ context.Context, _ *big.Int) (*state.ResolvedState, error) {
	return &state.ResolvedState{Latest: true, TransitionTimestamp: 0}, nil
}

func TestVerifyMessageWithSigProof_NonMerkalized(t *testing.T) {
	// TODO(illia-korotia): for non merklized claim and schema don't know about xsd:types
	t.Skip("skipping test")
	verifierID := "did:polygonid:polygon:mumbai:2qEevY9VnKdNsVDdXRv3qSLHRqoMGMRRdE5Gmc6iA7"
	callbackURL := "https://test.com/callback"
	reason := "test"

	var mtpProofRequest protocol.ZeroKnowledgeProofRequest
	mtpProofRequest.ID = 23
	mtpProofRequest.CircuitID = string(circuits.AtomicQuerySigV2CircuitID)
	opt := true
	mtpProofRequest.Optional = &opt
	mtpProofRequest.Query = map[string]interface{}{
		"allowedIssuers": []string{"*"},
		"credentialSubject": map[string]interface{}{
			"documentType": map[string]interface{}{
				"$eq": 10,
			},
		},
		"context": "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
		"type":    "KYCAgeCredential",
	}
	request := CreateAuthorizationRequestWithMessage(reason, "message to sign", verifierID, callbackURL)
	request.Body.Scope = append(request.Body.Scope, mtpProofRequest)

	userID := "did:polygonid:polygon:mumbai:2qD8Nsp4FQcdk1N3yhziquEBZGMXdVkKtBhtLdGnix"
	responseUUID := uuid.New()

	// response
	var message protocol.AuthorizationResponseMessage
	message.Typ = packers.MediaTypePlainMessage
	message.Type = protocol.AuthorizationResponseMessageType
	message.From = userID
	message.To = verifierID
	message.ID = responseUUID.String()
	message.ThreadID = request.ThreadID
	message.Body = protocol.AuthorizationMessageResponseBody{
		Message: "message to sign",
		Scope: []protocol.ZeroKnowledgeProofResponse{
			{
				ID:        23,
				CircuitID: mtpProofRequest.CircuitID,
				ZKProof: types.ZKProof{
					Proof: &types.ProofData{
						A: []string{
							"9518940539414587245794003192532307790550936491078690484579527365586406369952",
							"18310892073224615121155590891657868809375867436314025475318265897577698765429",
							"1",
						},
						B: [][]string{
							{
								"7473471862476301137207221898428038544241157556635980264621324015685573123570",
								"12749169234766877085006220937362504781288470732483056139299482729458259754028",
							},
							{
								"3455578419807762064145715564295939767903330673624118421238034929096545128331",
								"12484357578498567666992818368371681218686429789722992962435530253571008321433",
							},
							{
								"1",
								"0",
							}},
						C: []string{
							"2620490929586137686238649209251762311479806943644120771227616021811240503743",
							"5676385148800793701377781773804054339642731549886824415936348195774348094130",
							"1",
						},
						Protocol: "groth16",
					},
					PubSignals: []string{
						"0",
						"23280069646923371456510050373677752848804011824981226331232885668622242306",
						"2943483356559152311923412925436024635269538717812859789851139200242297094",
						"23",
						"22064883246134712298411652505170593669589088931416964593351226206090301954",
						"1",
						"2943483356559152311923412925436024635269538717812859789851139200242297094",
						"1642074362",
						"74977327600848231385663280181476307657",
						"0",
						"0",
						"2",
						"1",
						"10",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
					},
				},
			},
		},
	}

	schemaLoader := &mockJSONLDSchemaLoader{schema: kycV2Schema}
	authInstance, err := NewVerifier(verificationKeyloader, schemaLoader, stateResolvers)
	require.NoError(t, err)
	err = authInstance.VerifyAuthResponse(context.Background(), message, request)
	require.Nil(t, err)
}

func TestVerifyMessageWithMTPProof_Merkalized(t *testing.T) {
	verifierID := "did:polygonid:polygon:mumbai:2qEevY9VnKdNsVDdXRv3qSLHRqoMGMRRdE5Gmc6iA7"
	callbackURL := "https://test.com/callback"
	reason := "test"

	var mtpProofRequest protocol.ZeroKnowledgeProofRequest
	mtpProofRequest.ID = 23
	mtpProofRequest.CircuitID = string(circuits.AtomicQueryMTPV2CircuitID)
	opt := true
	mtpProofRequest.Optional = &opt
	mtpProofRequest.Query = map[string]interface{}{
		"allowedIssuers": []string{"*"},
		"credentialSubject": map[string]interface{}{
			"countryCode": map[string]interface{}{
				"$nin": []int{
					840,
					120,
					340,
					509,
				},
			},
		},
		"context": "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
		"type":    "KYCCountryOfResidenceCredential",
	}
	request := CreateAuthorizationRequestWithMessage(reason, "message to sign", verifierID, callbackURL)
	request.Body.Scope = append(request.Body.Scope, mtpProofRequest)

	userID := "did:polygonid:polygon:mumbai:2qPDLXDaU1xa1ERTb1XKBfPCB3o2wA46q49neiXWwY"
	responseUUID := uuid.New()

	// response
	var message protocol.AuthorizationResponseMessage
	message.Typ = packers.MediaTypePlainMessage
	message.Type = protocol.AuthorizationResponseMessageType
	message.From = userID
	message.To = verifierID
	message.ID = responseUUID.String()
	message.ThreadID = request.ThreadID
	message.Body = protocol.AuthorizationMessageResponseBody{
		Message: "message to sign",
		Scope: []protocol.ZeroKnowledgeProofResponse{
			{
				ID:        23,
				CircuitID: mtpProofRequest.CircuitID,
				ZKProof: types.ZKProof{
					Proof: &types.ProofData{
						A: []string{
							"261068577516437401613944053873182458364288414130914048345483377226144652651",
							"14191260071695980011679501808453222267520721767757759150101974382053161674611",
							"1",
						},
						B: [][]string{
							{
								"7670847844015116957526183728196977957312627307797919554134684901401436021977",
								"14957845472630017095821833222580194061266186851634053897768738253663253650835",
							},
							{
								"17835642458484628627556329876919077333912011235308758832172880012813397022104",
								"18100861130149678153133025031709897120097098591298817367491920553037011650228",
							},
							{
								"1",
								"0",
							}},
						C: []string{
							"6217865949299990642832523256863048932210546049203189113362851476966824162191",
							"19016949225277755690019647385855936969928994210905992628301967883803670436510",
							"1",
						},
						Protocol: "groth16",
					},
					PubSignals: []string{
						"1",
						"27152676987128542066808591998573000370436464722519513348891049644813718018",
						"23",
						"27752766823371471408248225708681313764866231655187366071881070918984471042",
						"21545768883509657340209171549441005603306012513932221371599501498534807719689",
						"1",
						"21545768883509657340209171549441005603306012513932221371599501498534807719689",
						"1679323038",
						"336615423900919464193075592850483704600",
						"0",
						"17002437119434618783545694633038537380726339994244684348913844923422470806844",
						"0",
						"5",
						"840",
						"120",
						"340",
						"509",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
					},
				},
			},
		},
	}

	schemaLoader := &mockJSONLDSchemaLoader{schema: kycV3Schema}
	authInstance, err := NewVerifier(verificationKeyloader, schemaLoader, stateResolvers)
	require.NoError(t, err)
	err = authInstance.VerifyAuthResponse(context.Background(), message, request)
	require.NoError(t, err)
}

func TestVerifier_VerifyJWZ(t *testing.T) {

	token := `eyJhbGciOiJncm90aDE2IiwiY2lyY3VpdElkIjoiYXV0aFYyIiwiY3JpdCI6WyJjaXJjdWl0SWQiXSwidHlwIjoiYXBwbGljYXRpb24vaWRlbjMtemtwLWpzb24ifQ.eyJpZCI6IjljMGY5NjIzLWM1NmMtNDEwNC04ODk2LWVjMjgyYTNiMmExNyIsInR5cCI6ImFwcGxpY2F0aW9uL2lkZW4zY29tbS1wbGFpbi1qc29uIiwidHlwZSI6Imh0dHBzOi8vaWRlbjMtY29tbXVuaWNhdGlvbi5pby9hdXRob3JpemF0aW9uLzEuMC9yZXNwb25zZSIsInRoaWQiOiI3ZjM4YTE5My0wOTE4LTRhNDgtOWZhYy0zNmFkZmRiOGI1NDIiLCJmcm9tIjoiZGlkOnBvbHlnb25pZDpwb2x5Z29uOm11bWJhaToycVBETFhEYVUxeGExRVJUYjFYS0JmUENCM28yd0E0NnE0OW5laVhXd1kiLCJ0byI6ImRpZDpwb2x5Z29uaWQ6cG9seWdvbjptdW1iYWk6MnFKNjg5a3BvSnhjU3pCNXNBRkp0UHNTQlNySEY1ZHE3MjJCSE1xVVJMIiwiYm9keSI6eyJkaWRfZG9jIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy9ucy9kaWQvdjEiXSwiaWQiOiJkaWQ6cG9seWdvbmlkOnBvbHlnb246bXVtYmFpOjJxUERMWERhVTF4YTFFUlRiMVhLQmZQQ0IzbzJ3QTQ2cTQ5bmVpWFd3WSIsInNlcnZpY2UiOlt7ImlkIjoiZGlkOnBvbHlnb25pZDpwb2x5Z29uOm11bWJhaToycVBETFhEYVUxeGExRVJUYjFYS0JmUENCM28yd0E0NnE0OW5laVhXd1kjcHVzaCIsInR5cGUiOiJwdXNoLW5vdGlmaWNhdGlvbiIsInNlcnZpY2VFbmRwb2ludCI6Imh0dHBzOi8vcHVzaC1zdGFnaW5nLnBvbHlnb25pZC5jb20vYXBpL3YxIiwibWV0YWRhdGEiOnsiZGV2aWNlcyI6W3siY2lwaGVydGV4dCI6InhZK3RHWHUrOWlHMHZ6dFpMTTlKN25PcDNRbE1Uci85TmI3Qjl5Q0prbDlxcUpiZ1AvMExOL1VmTkxxQUk4RWZIcFhJVlVlTmVVUmNCNm82bWVMVlpJK2VvMlhvcDM2SE1iK2JyQnJTTjRqVHZWVkRDQXVXSkI2akV5Q3ZNRzlMaXp6blBsS3VQSE15dEdCVnZnV0laRFZBeVdZbTFyMk9PUzc4OU5DZm41MnNjV0VRVW5VRWdnTmpyWjlLdFpmb09RMlBDbUpqRXpDejg0ZUc3RGM2bEFvbi8ycTJJNVlLQk12RkhnT3c4N25wb0owczVrQ1RVVENjeVRlQmg2VXpLQk5aNElibndvR3ZYcG9FelBVZXZRdjRGbXVTaExYYVF3Vk9nalRBUXR0T2g2SjZhcmE4UHNndVFGQ3dNUTlxV2JjTjZYdXlScjk4TVlqbGxpL0VEN09TZzBsWVU5cUdLa1RaL2ZZN2VWZkYyeFFhOWZXK01WVzlxM2NJMjJzbkRwV28xY1ZYNWt1TWhpbmFsajZXV1Q0OTAvblNXak1rZ3JkL25CdXNiMHR4eG1jWDU3QUowcVlyMkNsK0pQb1FhcExiOEFTT3dGYU5kRDRZV3pKWXRXVmlDbktMZ3dQNDFHaGl5NVNWZE1vbU1sUy9kSGo2TVZPMjNyOVRiTDFrRy8rdkFIZWF0YkdvZ3p1OWd3SzlJckF3WS95THhMYVpQcHZzdlJLWjVBa2E1b1pkbmRNNkdLUkM0OVhoVXloQnNlY0N2Z1hNeGZGNVBnWGhROVFTb1drMzFXSWRiWG5vbmU2YmVNQkpLUVYzemg2MmpoZUFuV3czZW16dndKajRUUHU4WTJQZ2lDL3FaZXhlUVlKdFNkelJXZUFjK2N5a2ZwTXA0SmdrV2hBPSIsImFsZyI6IlJTQS1PQUVQLTUxMiJ9XX19XX0sIm1lc3NhZ2UiOm51bGwsInNjb3BlIjpbeyJpZCI6MjMsImNpcmN1aXRJZCI6ImNyZWRlbnRpYWxBdG9taWNRdWVyeU1UUFYyIiwicHJvb2YiOnsicGlfYSI6WyIyNjEwNjg1Nzc1MTY0Mzc0MDE2MTM5NDQwNTM4NzMxODI0NTgzNjQyODg0MTQxMzA5MTQwNDgzNDU0ODMzNzcyMjYxNDQ2NTI2NTEiLCIxNDE5MTI2MDA3MTY5NTk4MDAxMTY3OTUwMTgwODQ1MzIyMjI2NzUyMDcyMTc2Nzc1Nzc1OTE1MDEwMTk3NDM4MjA1MzE2MTY3NDYxMSIsIjEiXSwicGlfYiI6W1siNzY3MDg0Nzg0NDAxNTExNjk1NzUyNjE4MzcyODE5Njk3Nzk1NzMxMjYyNzMwNzc5NzkxOTU1NDEzNDY4NDkwMTQwMTQzNjAyMTk3NyIsIjE0OTU3ODQ1NDcyNjMwMDE3MDk1ODIxODMzMjIyNTgwMTk0MDYxMjY2MTg2ODUxNjM0MDUzODk3NzY4NzM4MjUzNjYzMjUzNjUwODM1Il0sWyIxNzgzNTY0MjQ1ODQ4NDYyODYyNzU1NjMyOTg3NjkxOTA3NzMzMzkxMjAxMTIzNTMwODc1ODgzMjE3Mjg4MDAxMjgxMzM5NzAyMjEwNCIsIjE4MTAwODYxMTMwMTQ5Njc4MTUzMTMzMDI1MDMxNzA5ODk3MTIwMDk3MDk4NTkxMjk4ODE3MzY3NDkxOTIwNTUzMDM3MDExNjUwMjI4Il0sWyIxIiwiMCJdXSwicGlfYyI6WyI2MjE3ODY1OTQ5Mjk5OTkwNjQyODMyNTIzMjU2ODYzMDQ4OTMyMjEwNTQ2MDQ5MjAzMTg5MTEzMzYyODUxNDc2OTY2ODI0MTYyMTkxIiwiMTkwMTY5NDkyMjUyNzc3NTU2OTAwMTk2NDczODU4NTU5MzY5Njk5Mjg5OTQyMTA5MDU5OTI2MjgzMDE5Njc4ODM4MDM2NzA0MzY1MTAiLCIxIl0sInByb3RvY29sIjoiZ3JvdGgxNiIsImN1cnZlIjoiYm4xMjgifSwicHViX3NpZ25hbHMiOlsiMSIsIjI3MTUyNjc2OTg3MTI4NTQyMDY2ODA4NTkxOTk4NTczMDAwMzcwNDM2NDY0NzIyNTE5NTEzMzQ4ODkxMDQ5NjQ0ODEzNzE4MDE4IiwiMjMiLCIyNzc1Mjc2NjgyMzM3MTQ3MTQwODI0ODIyNTcwODY4MTMxMzc2NDg2NjIzMTY1NTE4NzM2NjA3MTg4MTA3MDkxODk4NDQ3MTA0MiIsIjIxNTQ1NzY4ODgzNTA5NjU3MzQwMjA5MTcxNTQ5NDQxMDA1NjAzMzA2MDEyNTEzOTMyMjIxMzcxNTk5NTAxNDk4NTM0ODA3NzE5Njg5IiwiMSIsIjIxNTQ1NzY4ODgzNTA5NjU3MzQwMjA5MTcxNTQ5NDQxMDA1NjAzMzA2MDEyNTEzOTMyMjIxMzcxNTk5NTAxNDk4NTM0ODA3NzE5Njg5IiwiMTY3OTMyMzAzOCIsIjMzNjYxNTQyMzkwMDkxOTQ2NDE5MzA3NTU5Mjg1MDQ4MzcwNDYwMCIsIjAiLCIxNzAwMjQzNzExOTQzNDYxODc4MzU0NTY5NDYzMzAzODUzNzM4MDcyNjMzOTk5NDI0NDY4NDM0ODkxMzg0NDkyMzQyMjQ3MDgwNjg0NCIsIjAiLCI1IiwiODQwIiwiMTIwIiwiMzQwIiwiNTA5IiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIl19XX19.eyJwcm9vZiI6eyJwaV9hIjpbIjcwMjI2MTEzODk5MzY1MDEzNDI2NTkwMjQ2Njk0NTczNTA3OTUwMTU5ODkzOTI1NzAzMDMwODQ4MzcyMTQ4MDc1MzYyNDg4NTE5MzYiLCIxMzg1OTcwODc3NTU0Mzk0Mjk3MTYxNTcxNTA1MTczNjM4MTc4NTEzODkzMjQ3ODc1Mzg3MjU5MTU0NDQxODk1ODkwOTU2MDQyOTU3NCIsIjEiXSwicGlfYiI6W1siMTE1MzQ5NjMxNDgwODQ0OTk0NDg5MDc3NzQxMTMxNjg1OTEyNDYyMjQ4OTg0MTU4ODAwMzY5NTA1MDYyMjU0ODkyMDA1NTc2NTA2NjUiLCIxNDA3MjA4Mjk1MTQ0Njc5NDk5MDk4NDcwNTE3ODA1OTY2NjI4NzM1NTEwNjc5MzUwMTg5MTE2ODgwNjE2NjUwMTUxMDkzMDY0MzQ0MSJdLFsiNDY3ODgyNDc3ODQ5ODA0NzE2OTEzNTk2NTg3MTYwNDgzNjkwMTQ1NjI5MDQ0NjQ0NjUzMzEyNzUwOTU4Mzg5MDU5MDkzNTY5ODQxNCIsIjEyODE5NzMwNTMyMDg0MTM4NDI0ODQ0MjExNDg4NjcxMTUyNDgwOTU1MzQ0MTA2NzU4NTE3NDEzODAxOTIzNTM3OTU3MzYzOTgwMjA0Il0sWyIxIiwiMCJdXSwicGlfYyI6WyIxNTUyMDYzNjk4OTY2MTg3NzExNDUwNjkwNDgxMDQxMzExNDI4NzQ5ODE1OTk2NDA5OTU2MTY5ODUyNjc4MzUwMDE1NjU1MjQzMDAwNCIsIjEyNjkyNzA3NDA3MTczMDg0OTM5NzQ1ODU5NzE0ODMxNDYyMDQ1ODg5NDA4NTk4NTI3MjU0ODA3NzkwNDk0NDY2Mjc5Njg3ODU5MjQ3IiwiMSJdLCJwcm90b2NvbCI6Imdyb3RoMTYiLCJjdXJ2ZSI6ImJuMTI4In0sInB1Yl9zaWduYWxzIjpbIjI3MTUyNjc2OTg3MTI4NTQyMDY2ODA4NTkxOTk4NTczMDAwMzcwNDM2NDY0NzIyNTE5NTEzMzQ4ODkxMDQ5NjQ0ODEzNzE4MDE4IiwiMTIxODQ5NzQwNzE0Mjc3NjgzNTIwMjcwMDM4NzgzMTkzMzgyNDkzODM4NDYxNjQ3MzAyMDQ1MDUzMjY5NTM1NTA2NDczOTExNzg4MDAiLCI4NzU2MDYwMjA1MDg2ODAzMzM1MjUyMzE5NzQ4NzQ4MzU0NzYxOTYxODE0MDEyNzI1NDk5ODczMzgyOTg4MDU2NDE4NjgwNjI4NjE5Il19`

	schemaLoader := &mockJSONLDSchemaLoader{schema: kycV101Schema}
	authInstance, err := NewVerifier(verificationKeyloader, schemaLoader, stateResolvers)
	require.NoError(t, err)
	parsedToken, err := authInstance.VerifyJWZ(context.Background(), token)
	require.NoError(t, err)
	require.Equal(t, parsedToken.Alg, "groth16")
}

func TestVerifier_FullVerify(t *testing.T) {
	// request
	verifierID := "did:polygonid:polygon:mumbai:2qEevY9VnKdNsVDdXRv3qSLHRqoMGMRRdE5Gmc6iA7"
	callbackURL := "https://test.com/callback"
	reason := "age verification"

	var mtpProofRequest protocol.ZeroKnowledgeProofRequest
	mtpProofRequest.ID = 23
	mtpProofRequest.CircuitID = string(circuits.AtomicQueryMTPV2CircuitID)
	opt := true
	mtpProofRequest.Optional = &opt
	mtpProofRequest.Query = map[string]interface{}{
		"allowedIssuers": []string{"*"},
		"credentialSubject": map[string]interface{}{
			"countryCode": map[string]interface{}{
				"$nin": []int{
					840,
					120,
					340,
					509,
				},
			},
		},
		"context": "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
		"type":    "KYCCountryOfResidenceCredential",
	}
	request := CreateAuthorizationRequestWithMessage(reason, "", verifierID, callbackURL)
	request.Body.Scope = append(request.Body.Scope, mtpProofRequest)
	request.ID = "28494007-9c49-4f1a-9694-7700c08865bf"
	request.ThreadID = "ee92ab12-2671-457e-aa5e-8158c205a985" // because it's used in the response

	token := `eyJhbGciOiJncm90aDE2IiwiY2lyY3VpdElkIjoiYXV0aFYyIiwiY3JpdCI6WyJjaXJjdWl0SWQiXSwidHlwIjoiYXBwbGljYXRpb24vaWRlbjMtemtwLWpzb24ifQ.eyJpZCI6IjljMGY5NjIzLWM1NmMtNDEwNC04ODk2LWVjMjgyYTNiMmExNyIsInR5cCI6ImFwcGxpY2F0aW9uL2lkZW4zY29tbS1wbGFpbi1qc29uIiwidHlwZSI6Imh0dHBzOi8vaWRlbjMtY29tbXVuaWNhdGlvbi5pby9hdXRob3JpemF0aW9uLzEuMC9yZXNwb25zZSIsInRoaWQiOiI3ZjM4YTE5My0wOTE4LTRhNDgtOWZhYy0zNmFkZmRiOGI1NDIiLCJmcm9tIjoiZGlkOnBvbHlnb25pZDpwb2x5Z29uOm11bWJhaToycVBETFhEYVUxeGExRVJUYjFYS0JmUENCM28yd0E0NnE0OW5laVhXd1kiLCJ0byI6ImRpZDpwb2x5Z29uaWQ6cG9seWdvbjptdW1iYWk6MnFKNjg5a3BvSnhjU3pCNXNBRkp0UHNTQlNySEY1ZHE3MjJCSE1xVVJMIiwiYm9keSI6eyJkaWRfZG9jIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy9ucy9kaWQvdjEiXSwiaWQiOiJkaWQ6cG9seWdvbmlkOnBvbHlnb246bXVtYmFpOjJxUERMWERhVTF4YTFFUlRiMVhLQmZQQ0IzbzJ3QTQ2cTQ5bmVpWFd3WSIsInNlcnZpY2UiOlt7ImlkIjoiZGlkOnBvbHlnb25pZDpwb2x5Z29uOm11bWJhaToycVBETFhEYVUxeGExRVJUYjFYS0JmUENCM28yd0E0NnE0OW5laVhXd1kjcHVzaCIsInR5cGUiOiJwdXNoLW5vdGlmaWNhdGlvbiIsInNlcnZpY2VFbmRwb2ludCI6Imh0dHBzOi8vcHVzaC1zdGFnaW5nLnBvbHlnb25pZC5jb20vYXBpL3YxIiwibWV0YWRhdGEiOnsiZGV2aWNlcyI6W3siY2lwaGVydGV4dCI6InhZK3RHWHUrOWlHMHZ6dFpMTTlKN25PcDNRbE1Uci85TmI3Qjl5Q0prbDlxcUpiZ1AvMExOL1VmTkxxQUk4RWZIcFhJVlVlTmVVUmNCNm82bWVMVlpJK2VvMlhvcDM2SE1iK2JyQnJTTjRqVHZWVkRDQXVXSkI2akV5Q3ZNRzlMaXp6blBsS3VQSE15dEdCVnZnV0laRFZBeVdZbTFyMk9PUzc4OU5DZm41MnNjV0VRVW5VRWdnTmpyWjlLdFpmb09RMlBDbUpqRXpDejg0ZUc3RGM2bEFvbi8ycTJJNVlLQk12RkhnT3c4N25wb0owczVrQ1RVVENjeVRlQmg2VXpLQk5aNElibndvR3ZYcG9FelBVZXZRdjRGbXVTaExYYVF3Vk9nalRBUXR0T2g2SjZhcmE4UHNndVFGQ3dNUTlxV2JjTjZYdXlScjk4TVlqbGxpL0VEN09TZzBsWVU5cUdLa1RaL2ZZN2VWZkYyeFFhOWZXK01WVzlxM2NJMjJzbkRwV28xY1ZYNWt1TWhpbmFsajZXV1Q0OTAvblNXak1rZ3JkL25CdXNiMHR4eG1jWDU3QUowcVlyMkNsK0pQb1FhcExiOEFTT3dGYU5kRDRZV3pKWXRXVmlDbktMZ3dQNDFHaGl5NVNWZE1vbU1sUy9kSGo2TVZPMjNyOVRiTDFrRy8rdkFIZWF0YkdvZ3p1OWd3SzlJckF3WS95THhMYVpQcHZzdlJLWjVBa2E1b1pkbmRNNkdLUkM0OVhoVXloQnNlY0N2Z1hNeGZGNVBnWGhROVFTb1drMzFXSWRiWG5vbmU2YmVNQkpLUVYzemg2MmpoZUFuV3czZW16dndKajRUUHU4WTJQZ2lDL3FaZXhlUVlKdFNkelJXZUFjK2N5a2ZwTXA0SmdrV2hBPSIsImFsZyI6IlJTQS1PQUVQLTUxMiJ9XX19XX0sIm1lc3NhZ2UiOm51bGwsInNjb3BlIjpbeyJpZCI6MjMsImNpcmN1aXRJZCI6ImNyZWRlbnRpYWxBdG9taWNRdWVyeU1UUFYyIiwicHJvb2YiOnsicGlfYSI6WyIyNjEwNjg1Nzc1MTY0Mzc0MDE2MTM5NDQwNTM4NzMxODI0NTgzNjQyODg0MTQxMzA5MTQwNDgzNDU0ODMzNzcyMjYxNDQ2NTI2NTEiLCIxNDE5MTI2MDA3MTY5NTk4MDAxMTY3OTUwMTgwODQ1MzIyMjI2NzUyMDcyMTc2Nzc1Nzc1OTE1MDEwMTk3NDM4MjA1MzE2MTY3NDYxMSIsIjEiXSwicGlfYiI6W1siNzY3MDg0Nzg0NDAxNTExNjk1NzUyNjE4MzcyODE5Njk3Nzk1NzMxMjYyNzMwNzc5NzkxOTU1NDEzNDY4NDkwMTQwMTQzNjAyMTk3NyIsIjE0OTU3ODQ1NDcyNjMwMDE3MDk1ODIxODMzMjIyNTgwMTk0MDYxMjY2MTg2ODUxNjM0MDUzODk3NzY4NzM4MjUzNjYzMjUzNjUwODM1Il0sWyIxNzgzNTY0MjQ1ODQ4NDYyODYyNzU1NjMyOTg3NjkxOTA3NzMzMzkxMjAxMTIzNTMwODc1ODgzMjE3Mjg4MDAxMjgxMzM5NzAyMjEwNCIsIjE4MTAwODYxMTMwMTQ5Njc4MTUzMTMzMDI1MDMxNzA5ODk3MTIwMDk3MDk4NTkxMjk4ODE3MzY3NDkxOTIwNTUzMDM3MDExNjUwMjI4Il0sWyIxIiwiMCJdXSwicGlfYyI6WyI2MjE3ODY1OTQ5Mjk5OTkwNjQyODMyNTIzMjU2ODYzMDQ4OTMyMjEwNTQ2MDQ5MjAzMTg5MTEzMzYyODUxNDc2OTY2ODI0MTYyMTkxIiwiMTkwMTY5NDkyMjUyNzc3NTU2OTAwMTk2NDczODU4NTU5MzY5Njk5Mjg5OTQyMTA5MDU5OTI2MjgzMDE5Njc4ODM4MDM2NzA0MzY1MTAiLCIxIl0sInByb3RvY29sIjoiZ3JvdGgxNiIsImN1cnZlIjoiYm4xMjgifSwicHViX3NpZ25hbHMiOlsiMSIsIjI3MTUyNjc2OTg3MTI4NTQyMDY2ODA4NTkxOTk4NTczMDAwMzcwNDM2NDY0NzIyNTE5NTEzMzQ4ODkxMDQ5NjQ0ODEzNzE4MDE4IiwiMjMiLCIyNzc1Mjc2NjgyMzM3MTQ3MTQwODI0ODIyNTcwODY4MTMxMzc2NDg2NjIzMTY1NTE4NzM2NjA3MTg4MTA3MDkxODk4NDQ3MTA0MiIsIjIxNTQ1NzY4ODgzNTA5NjU3MzQwMjA5MTcxNTQ5NDQxMDA1NjAzMzA2MDEyNTEzOTMyMjIxMzcxNTk5NTAxNDk4NTM0ODA3NzE5Njg5IiwiMSIsIjIxNTQ1NzY4ODgzNTA5NjU3MzQwMjA5MTcxNTQ5NDQxMDA1NjAzMzA2MDEyNTEzOTMyMjIxMzcxNTk5NTAxNDk4NTM0ODA3NzE5Njg5IiwiMTY3OTMyMzAzOCIsIjMzNjYxNTQyMzkwMDkxOTQ2NDE5MzA3NTU5Mjg1MDQ4MzcwNDYwMCIsIjAiLCIxNzAwMjQzNzExOTQzNDYxODc4MzU0NTY5NDYzMzAzODUzNzM4MDcyNjMzOTk5NDI0NDY4NDM0ODkxMzg0NDkyMzQyMjQ3MDgwNjg0NCIsIjAiLCI1IiwiODQwIiwiMTIwIiwiMzQwIiwiNTA5IiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIl19XX19.eyJwcm9vZiI6eyJwaV9hIjpbIjcwMjI2MTEzODk5MzY1MDEzNDI2NTkwMjQ2Njk0NTczNTA3OTUwMTU5ODkzOTI1NzAzMDMwODQ4MzcyMTQ4MDc1MzYyNDg4NTE5MzYiLCIxMzg1OTcwODc3NTU0Mzk0Mjk3MTYxNTcxNTA1MTczNjM4MTc4NTEzODkzMjQ3ODc1Mzg3MjU5MTU0NDQxODk1ODkwOTU2MDQyOTU3NCIsIjEiXSwicGlfYiI6W1siMTE1MzQ5NjMxNDgwODQ0OTk0NDg5MDc3NzQxMTMxNjg1OTEyNDYyMjQ4OTg0MTU4ODAwMzY5NTA1MDYyMjU0ODkyMDA1NTc2NTA2NjUiLCIxNDA3MjA4Mjk1MTQ0Njc5NDk5MDk4NDcwNTE3ODA1OTY2NjI4NzM1NTEwNjc5MzUwMTg5MTE2ODgwNjE2NjUwMTUxMDkzMDY0MzQ0MSJdLFsiNDY3ODgyNDc3ODQ5ODA0NzE2OTEzNTk2NTg3MTYwNDgzNjkwMTQ1NjI5MDQ0NjQ0NjUzMzEyNzUwOTU4Mzg5MDU5MDkzNTY5ODQxNCIsIjEyODE5NzMwNTMyMDg0MTM4NDI0ODQ0MjExNDg4NjcxMTUyNDgwOTU1MzQ0MTA2NzU4NTE3NDEzODAxOTIzNTM3OTU3MzYzOTgwMjA0Il0sWyIxIiwiMCJdXSwicGlfYyI6WyIxNTUyMDYzNjk4OTY2MTg3NzExNDUwNjkwNDgxMDQxMzExNDI4NzQ5ODE1OTk2NDA5OTU2MTY5ODUyNjc4MzUwMDE1NjU1MjQzMDAwNCIsIjEyNjkyNzA3NDA3MTczMDg0OTM5NzQ1ODU5NzE0ODMxNDYyMDQ1ODg5NDA4NTk4NTI3MjU0ODA3NzkwNDk0NDY2Mjc5Njg3ODU5MjQ3IiwiMSJdLCJwcm90b2NvbCI6Imdyb3RoMTYiLCJjdXJ2ZSI6ImJuMTI4In0sInB1Yl9zaWduYWxzIjpbIjI3MTUyNjc2OTg3MTI4NTQyMDY2ODA4NTkxOTk4NTczMDAwMzcwNDM2NDY0NzIyNTE5NTEzMzQ4ODkxMDQ5NjQ0ODEzNzE4MDE4IiwiMTIxODQ5NzQwNzE0Mjc3NjgzNTIwMjcwMDM4NzgzMTkzMzgyNDkzODM4NDYxNjQ3MzAyMDQ1MDUzMjY5NTM1NTA2NDczOTExNzg4MDAiLCI4NzU2MDYwMjA1MDg2ODAzMzM1MjUyMzE5NzQ4NzQ4MzU0NzYxOTYxODE0MDEyNzI1NDk5ODczMzgyOTg4MDU2NDE4NjgwNjI4NjE5Il19`

	schemaLoader := &mockJSONLDSchemaLoader{schema: kycV3Schema}
	authInstance, err := NewVerifier(verificationKeyloader, schemaLoader, stateResolvers)
	require.NoError(t, err)
	_, err = authInstance.FullVerify(context.Background(), token, request)
	require.NoError(t, err)
}

func TestVerifier_FullVerify_JWS(t *testing.T) {
	var request protocol.AuthorizationRequestMessage

	request.Typ = packers.MediaTypeSignedMessage
	request.Type = protocol.AuthorizationRequestMessageType
	request.ID = "4f3549b-0c9d-47f8-968c-c9b0c10b8847"
	request.ThreadID = "1f3549b-0c9d-47f8-968c-c9b0c10b8847"
	request.Body = protocol.AuthorizationRequestMessageBody{
		CallbackURL: "https://test.com/callback",
		Reason:      "reason",
		Scope:       []protocol.ZeroKnowledgeProofRequest{},
	}
	request.From = "did:iden3:polygon:mumbai:x4jcHP4XHTK3vX58AHZPyHE8kYjneyE6FZRfz7K29"
	request.To = "did:polygonid:polygon:mumbai:2qEevY9VnKdNsVDdXRv3qSLHRqoMGMRRdE5Gmc6iA7"

	token := `eyJhbGciOiJFUzI1NksiLCJraWQiOiJkaWQ6aWRlbjM6cG9seWdvbjptdW1iYWk6eDRqY0hQNFhIVEszdlg1OEFIWlB5SEU4a1lqbmV5RTZGWlJmejdLMjkiLCJ0eXAiOiJhcHBsaWNhdGlvbi9pZGVuM2NvbW0tc2lnbmVkLWpzb24ifQ.eyJ0eXBlIjoiaHR0cHM6Ly9pZGVuMy1jb21tdW5pY2F0aW9uLmlvL2F1dGhvcml6YXRpb24vMS4wL3Jlc3BvbnNlIiwiZnJvbSI6ImRpZDppZGVuMzpwb2x5Z29uOm11bWJhaTp4NGpjSFA0WEhUSzN2WDU4QUhaUHlIRThrWWpuZXlFNkZaUmZ6N0syOSIsInRvIjoiZGlkOnBvbHlnb25pZDpwb2x5Z29uOm11bWJhaToycUVldlk5Vm5LZE5zVkRkWFJ2M3FTTEhScW9NR01SUmRFNUdtYzZpQTciLCJ0eXAiOiJhcHBsaWNhdGlvbi9pZGVuM2NvbW0tc2lnbmVkLWpzb24iLCJ0aGlkIjoiMWYzNTQ5Yi0wYzlkLTQ3ZjgtOTY4Yy1jOWIwYzEwYjg4NDciLCJpZCI6IjRmMzU0OWItMGM5ZC00N2Y4LTk2OGMtYzliMGMxMGI4ODQ3IiwiYm9keSI6eyJzY29wZSI6W119fQ.9J0EPmZuncXMUiDSHUzOcvw7gahcVkIFA7oX9akJpdQUk6H-vNE2m31CSeXKJayF4K9LZoyE9hds2BflitcXtQ`

	schemaLoader := &mockJSONLDSchemaLoader{schema: kycV3Schema}
	v, err := NewVerifier(verificationKeyloader, schemaLoader, stateResolvers)
	require.NoError(t, err)
	pm := *iden3comm.NewPackageManager()
	jwsPacker := packers.NewJWSPacker(didResolverHandler, nil)

	err = pm.RegisterPackers(jwsPacker)
	require.NoError(t, err)
	v.SetPackageManager(pm)
	_, err = v.FullVerify(context.Background(), token, request)
	require.NoError(t, err)
}

func TestVerifyAuthResponseWithEmptyReq(t *testing.T) {
	t.Skip("non-merklized claims are not supported")

	verifierID := "did:polygonid:polygon:mumbai:2qEevY9VnKdNsVDdXRv3qSLHRqoMGMRRdE5Gmc6iA7"
	callbackURL := "https://test.com/callback"
	reason := "test"

	userID := "did:polygonid:polygon:mumbai:2qD8Nsp4FQcdk1N3yhziquEBZGMXdVkKtBhtLdGnix"
	var zkReq protocol.ZeroKnowledgeProofRequest
	zkReq.ID = 23
	zkReq.CircuitID = string(circuits.AtomicQuerySigV2CircuitID)
	opt := true
	zkReq.Optional = &opt
	zkReq.Query = map[string]interface{}{
		"allowedIssuers": []string{"*"},
		"context":        "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
		"type":           "KYCAgeCredential",
	}

	authReq := CreateAuthorizationRequestWithMessage(reason, "test", verifierID, callbackURL)
	authReq.Body.Scope = append(authReq.Body.Scope, zkReq)
	authReq.ID = "28494007-9c49-4f1a-9694-7700c08865bf"
	authReq.ThreadID = "7f38a193-0918-4a48-9fac-36adfdb8b542"

	// response
	resp := protocol.AuthorizationResponseMessage{
		ID:       "1",
		Typ:      "application/iden3comm-plain-json",
		Type:     "https://iden3-communication.io/authorization/1.0/response",
		ThreadID: authReq.ThreadID,
		Body: protocol.AuthorizationMessageResponseBody{
			Message: "test",
			Scope: []protocol.ZeroKnowledgeProofResponse{
				{
					ID:        23,
					CircuitID: string(circuits.AtomicQuerySigV2CircuitID),
					ZKProof: types.ZKProof{
						Proof: &types.ProofData{
							A: []string{
								"9842063851166899357608339265674332708045063650629323669848120342194679808076",
								"16206954115086409123668950271515758924555963980494493510855476478591822404827",
								"1",
							},
							B: [][]string{
								{
									"5545535720422947171459387662245741010162970511259433941703524281908236057668",
									"10561444885633079418413567831528236222511254998093130837955795587671392481895",
								},
								{
									"12832733708698041875897779399574055232051553662135872243100477516512773082967",
									"9817420633398166811616613261515725671943907865363970047192668444892570410329",
								},
								{
									"1",
									"0",
								}},
							C: []string{
								"15730764089701951976631362836516364492331983136934339494373153516632793542908",
								"6678992215432400449623605365468322210942926642059613422963275672866160988129",
								"1",
							},
							Protocol: "groth16",
						},
						PubSignals: []string{
							"0",
							"23280069646923371456510050373677752848804011824981226331232885668622242306",
							"2943483356559152311923412925436024635269538717812859789851139200242297094",
							"23",
							"22064883246134712298411652505170593669589088931416964593351226206090301954",
							"1",
							"2943483356559152311923412925436024635269538717812859789851139200242297094",
							"1642074362",
							"74977327600848231385663280181476307657",
							"0",
							"0",
							"2",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
						},
					},
				},
			},
		},
		From: userID,
		To:   authReq.From,
	}

	schemaLoader := &mockJSONLDSchemaLoader{schema: kycV2Schema}
	authInstance, err := NewVerifier(verificationKeyloader, schemaLoader, stateResolvers)
	require.NoError(t, err)
	err = authInstance.VerifyAuthResponse(context.Background(), resp, authReq)
	require.NoError(t, err)
}

func TestCreateAuthorizationRequest(t *testing.T) {

	sender := "did:polygonid:polygon:mumbai:2qEevY9VnKdNsVDdXRv3qSLHRqoMGMRRdE5Gmc6iA7"
	callbackURL := "https://test.com/callback"
	reason := "basic authentication"

	request := CreateAuthorizationRequest(reason, sender, callbackURL)
	assert.Len(t, request.Body.Scope, 0)
	assert.Equal(t, callbackURL, request.Body.CallbackURL)
	assert.Equal(t, sender, request.From)
	assert.Equal(t, protocol.AuthorizationRequestMessageType, request.Type)

}

func TestCreateAuthorizationRequestWithMessage(t *testing.T) {

	sender := "did:polygonid:polygon:mumbai:2qEevY9VnKdNsVDdXRv3qSLHRqoMGMRRdE5Gmc6iA7"
	callbackURL := "https://test.com/callback"
	reason := "basic authentication"
	message := "message"

	request := CreateAuthorizationRequestWithMessage(reason, message, sender, callbackURL)
	assert.Len(t, request.Body.Scope, 0)
	assert.Equal(t, callbackURL, request.Body.CallbackURL)
	assert.Equal(t, sender, request.From)
	assert.Equal(t, protocol.AuthorizationRequestMessageType, request.Type)
	assert.Equal(t, message, request.Body.Message)
}

func TestVerifier_FullVerifySelectiveDisclosure(t *testing.T) {
	// request
	verifierID := "did:polygonid:polygon:mumbai:2qEevY9VnKdNsVDdXRv3qSLHRqoMGMRRdE5Gmc6iA7"
	callbackURL := "https://test.com/callback"
	reason := "age verification"

	var mtpProofRequest protocol.ZeroKnowledgeProofRequest
	mtpProofRequest.ID = 1
	mtpProofRequest.CircuitID = string(circuits.AtomicQueryMTPV2CircuitID)
	opt := true
	mtpProofRequest.Optional = &opt
	mtpProofRequest.Query = map[string]interface{}{
		"allowedIssuers": []string{"*"},
		"credentialSubject": map[string]interface{}{
			"birthday": map[string]interface{}{},
		},
		"context": "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v4.jsonld",
		"type":    "KYCAgeCredential",
	}
	request := CreateAuthorizationRequestWithMessage(reason, "", verifierID, callbackURL)
	request.Body.Scope = append(request.Body.Scope, mtpProofRequest)
	request.ID = "28494007-9c49-4f1a-9694-7700c08865bf"
	request.ThreadID = "ee92ab12-2671-457e-aa5e-8158c205a985" // because it's used in the response

	token := `eyJhbGciOiJncm90aDE2IiwiY2lyY3VpdElkIjoiYXV0aFYyIiwiY3JpdCI6WyJjaXJjdWl0SWQiXSwidHlwIjoiYXBwbGljYXRpb24vaWRlbjMtemtwLWpzb24ifQ.eyJpZCI6ImE2ZWM2ZTE5LWQwYzAtNDUxYi04NDg3LWRhODAwZGMzMDgxOCIsInR5cCI6ImFwcGxpY2F0aW9uL2lkZW4zY29tbS1wbGFpbi1qc29uIiwidHlwZSI6Imh0dHBzOi8vaWRlbjMtY29tbXVuaWNhdGlvbi5pby9hdXRob3JpemF0aW9uLzEuMC9yZXNwb25zZSIsInRoaWQiOiI3ZjM4YTE5My0wOTE4LTRhNDgtOWZhYy0zNmFkZmRiOGI1NDIiLCJmcm9tIjoiZGlkOnBvbHlnb25pZDpwb2x5Z29uOm11bWJhaToycUpwUnFaTlJUeGtpQ1VONFZTZkxRN0tBNFB6SFN3d1Z3blNLU0ZLdHciLCJ0byI6ImRpZDpwb2x5Z29uaWQ6cG9seWdvbjptdW1iYWk6MnFKNjg5a3BvSnhjU3pCNXNBRkp0UHNTQlNySEY1ZHE3MjJCSE1xVVJMIiwiYm9keSI6eyJkaWRfZG9jIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy9ucy9kaWQvdjEiXSwiaWQiOiJkaWQ6cG9seWdvbmlkOnBvbHlnb246bXVtYmFpOjJxSnBScVpOUlR4a2lDVU40VlNmTFE3S0E0UHpIU3d3VnduU0tTRkt0dyIsInNlcnZpY2UiOlt7ImlkIjoiZGlkOnBvbHlnb25pZDpwb2x5Z29uOm11bWJhaToycUpwUnFaTlJUeGtpQ1VONFZTZkxRN0tBNFB6SFN3d1Z3blNLU0ZLdHcjcHVzaCIsInR5cGUiOiJwdXNoLW5vdGlmaWNhdGlvbiIsInNlcnZpY2VFbmRwb2ludCI6Imh0dHBzOi8vcHVzaC1zdGFnaW5nLnBvbHlnb25pZC5jb20vYXBpL3YxIiwibWV0YWRhdGEiOnsiZGV2aWNlcyI6W3siY2lwaGVydGV4dCI6IlBoeGlRbVRqQjg1MmsvSGV1by9Wd0NuZE9keUdvblVaQThmbUN3L0pWZC9rajNGMG9uUUtwRWFUZXVsZnBMM0p3cnF1RVplT0RyVm1VOU9hbWo3eEpMV3pNOC9RSmptUG5aMzIyMmFGbGVtTGlSNnhGNk5ZZzNZMUZtVitMdlYrUUUwV0lsVHByUlVUSGhYNDJWQTcveWUvSGI5bStZSFJiUXNSa3FiQzVCYjQ2bE9IOFFjWjJ5OTEzOXVCYTlGUk9ERE5XNzViRytNR1ZjMUhBMnJ3aFQzNjVGMkIvSEtaWkpKVE02TEZhL1U3bjVjaVFMb2lyam5tei9RYVFvRmpVWHI5QUFtdkFkbFl3VkNIeDZhdVp1SnlXUjRRT1kxYm0rdG5mSWJmYnFBL2pNUUVlcE9ydittZENSY2VLaFI1ZDMzaFVld1VRakJrNFdxNHZQUy9HMlhLUUlUa1BCNnM5aGFwSkpYL3YrRHVBUWE2MnVEcFQ5UExYWjRBbW1PUUdlYXZWd1BTOE1QSHdoUHZHS0wxbWluVmlxY1BIUDU5dHZTUVlxRTVncU5lQVpPSVY3RW4wcU1SMHVDb0RFQ0Q1Sk55VFJvRXFIeTlIR2hjZ0tOTXdlL3VyZTlJdGV6UlZmSm9KbzgxcHVSZE82Y1daZnVjY2s0U1VndTJGRFdCUndrWU9McGFlempvbEZOZ0xyU2ltbzJZQ2t5U0lFRHRNcjAyR0h0T0RSS25vMFZjUTdLZkUyQ0VNSStZVXlQTkQ4Mk9OeDBGc0ZMQU9qMXAxNVBjbDF0bnhWWUJKZmJYNXNZM3BpcDI5NU5jY3VIT3RFQndwQzhoS0toWjJ5SHpsOGhQNlpGcWJlckM0TlRPMFo4a2NtZFVEd01vM1pJS2QyNDZiRnlxV2dNPSIsImFsZyI6IlJTQS1PQUVQLTUxMiJ9XX19XX0sIm1lc3NhZ2UiOm51bGwsInNjb3BlIjpbeyJpZCI6MSwiY2lyY3VpdElkIjoiY3JlZGVudGlhbEF0b21pY1F1ZXJ5TVRQVjIiLCJwcm9vZiI6eyJwaV9hIjpbIjE3MDc5OTEzMTQ1NzIwMjExODY5OTc4Njk3NTQ1NzkzNDc3OTc4ODc2NzUzNjE4MDA4NjAxNzI3MjA5NjU2MjU2NDAzOTg0MTE5MDEzIiwiMTg5MjU4NTgyNzkxMDg5ODMxMTAwMjU5NTc4NTM5MTI1NTU5MDU5Nzg2OTg5ODE5NjA5MDc0NTg0OTUyNDUyODYzMDQ4MDUwNzA5NjgiLCIxIl0sInBpX2IiOltbIjcyMDM2MzA2NTA5NzQ2MDUxODg0MTc5Mjc2Mzk1NTIxMjEwMDUyMTg5NTM2Njg5NDE5MDQxOTQyMjg1MDYzOTE4NTAyMDA0NjkzMDUiLCIxNDIzNTM0OTU2MzkzOTc3ODE1ODI3OTM2MzExMjQ1MTM2MjI1MTI1MTQyMzk0MTE5ODczODI2MzIxNzkzOTYwNzg0ODk0MTc2ODQ5MCJdLFsiMjA1NjkyMjYyNzYyMjU2ODczMDgyNjEyNTA2ODIxODU2MTc5MTQ4MDkzOTg2NzA4OTIwODc4NjUxMjM1MzgyNjUzMjE4MDc0Njc0MyIsIjE5MjA5MjEyNjA0MTk0NzA1Mzk5MDA1Mjc1MDc0MDg2ODI3MTg2MDc2NzQ1NTE0MzgwMzAxMDM5NTU3Njk3MDg1NDkwMjI5ODUyNDM5Il0sWyIxIiwiMCJdXSwicGlfYyI6WyIxMDEzMjAyMzEyNDUwNjcyODI2MjU4MTI1MjU1ODAxOTc3MjU4MzkwNjk4NjkwNzExNzMwMDE4MTkyNDUzMTg2MDU3MDMyMzMzNzk0MyIsIjczNjIyMTI1MDIyMDg3OTU3MzUzNDcwMjE2MTM3MzU1MjMyNDM5MjM2NzUwNzM2NjgyMjU4MDM5MDE0MzE0NzA4OTE3Mzc4MTU3MzMiLCIxIl0sInByb3RvY29sIjoiZ3JvdGgxNiIsImN1cnZlIjoiYm4xMjgifSwicHViX3NpZ25hbHMiOlsiMSIsIjIxNTEzMTQwNTMwMjMzOTIxNTE1ODA5MjM1Mzg4NzgwMTM0NjgxMjQ1NjEyODU4NzQ0OTAwMjk3NzQwNDkwNDQ3NzM4NTczMzE0IiwiMSIsIjI3NzUyNzY2ODIzMzcxNDcxNDA4MjQ4MjI1NzA4NjgxMzEzNzY0ODY2MjMxNjU1MTg3MzY2MDcxODgxMDcwOTE4OTg0NDcxMDQyIiwiMjI5ODI1ODk3MDg5OTY4NTE2NzUxMTE5NDA0OTkyMzY5NTkxOTEzNzcyMDg5NDUyNTQ2ODMzNTg1NzA1NzY1NTIyMTA5ODkyNDk3MyIsIjEiLCIyMjk4MjU4OTcwODk5Njg1MTY3NTExMTk0MDQ5OTIzNjk1OTE5MTM3NzIwODk0NTI1NDY4MzM1ODU3MDU3NjU1MjIxMDk4OTI0OTczIiwiMTY4MTM4MTA3NSIsIjI2NzgzMTUyMTkyMjU1ODAyNzIwNjA4MjM5MDA0MzMyMTc5Njk0NCIsIjAiLCIyMDM3NjAzMzgzMjM3MTEwOTE3NzY4MzA0ODQ1NjAxNDUyNTkwNTExOTE3MzY3NDk4NTg0MzkxNTQ0NTYzNDcyNjE2NzQ1MDk4OTYzMCIsIjAiLCIxIiwiMTk5NjA0MjQiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiXSwidnAiOnsiQHR5cGUiOiJWZXJpZmlhYmxlUHJlc2VudGF0aW9uIiwiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiXSwidmVyaWZpYWJsZUNyZWRlbnRpYWwiOnsiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiLCJodHRwczovL3Jhdy5naXRodWJ1c2VyY29udGVudC5jb20vaWRlbjMvY2xhaW0tc2NoZW1hLXZvY2FiL21haW4vc2NoZW1hcy9qc29uLWxkL2t5Yy12NC5qc29ubGQiXSwiQHR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJLWUNBZ2VDcmVkZW50aWFsIl0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7IkB0eXBlIjoiS1lDQWdlQ3JlZGVudGlhbCIsImJpcnRoZGF5IjoxOTk2MDQyNH19fX1dfX0.eyJwcm9vZiI6eyJwaV9hIjpbIjkzOTkyOTEyMjUxMDI1NDc2MDExMTI4ODMwOTM1NzQ0MTU5MzUzMzU5ODIwODgyMTg2NDE5ODg5NTgwMzIzODA1MTIyNTczOTY0OTMiLCIxMDMxNDYxNzA0NjQ0ODIzNjE4MTkzNjYxODUwMTMzMDY0Njc2MjU3OTU1MTkxNTE1NTY5MTU4ODU5NTk4NjYzNzY4Mzc1OTE4NTczNCIsIjEiXSwicGlfYiI6W1siMTc3MDczODkwMDE3MTg2NDk4NTIyMjMyNjA1Mjk2Mzg2Mjg1OTc1NzIyOTU0MzU4MDY3Mjg0MTEyMTc0MTQwMDY4NDI1NTg3NDk1OTMiLCIyMTU2Nzc4MDgwMTMyNzU0NTc5ODk0NzkzMjIwODAzOTA3NjYyMTM0NDg3NzQ3NzU5NDQ1NzA2MDc5OTQwMzI1NjYyNzY5MTU1Njg0MSJdLFsiMjA3NzY4ODY1ODkwNzE2OTU3NDczMTUzODIyNjI5MjU0NzI3MzA2NTY3OTE5NDI5ODg0MjI2Mzk0NTAzMTEzODE4MjM3NTU1ODI0MCIsIjE0MzA5NTc3MDk4OTk3OTQ1Njc4OTM1MjgwMzgxMTE0NzI5MzY2NTU1MDIyODk5MTE2NTc5NjQ2NTI3NjEwMjYxOTIwMTg3NTEwNjUxIl0sWyIxIiwiMCJdXSwicGlfYyI6WyIyMTE4ODk1MDUwMjY2OTk0Njk0NjAzMzUzNTYyNTk1MjE5MjY1MTY2ODI2MjkyNDIyNzAyMDg2OTU3MDM0NjAyODE4OTc2MzM2MDk3NCIsIjgxODQ1NzY2ODU3MDk5MTY4NzA3ODkxNjgxOTI1MjIzMzg4NDQzNDMxNzk0NzgxMjY5NzI4MTE2NjQxMTY2NzIwOTY1MjAxNjU0NjkiLCIxIl0sInByb3RvY29sIjoiZ3JvdGgxNiIsImN1cnZlIjoiYm4xMjgifSwicHViX3NpZ25hbHMiOlsiMjE1MTMxNDA1MzAyMzM5MjE1MTU4MDkyMzUzODg3ODAxMzQ2ODEyNDU2MTI4NTg3NDQ5MDAyOTc3NDA0OTA0NDc3Mzg1NzMzMTQiLCI0MzA0NjAwNjM3MTg5NzI2OTU0Nzg4MTMzNDIxNjc0ODk0NzYxODQ0OTE2MDgyMTY2MjgyMzA4MDAyMDY1MDI4NTY4ODY0Mjg5Njc1IiwiNTIyOTY2ODY4NjU1NzYzNzAxNzc4MTE1NzM1NjMwNDc2OTY2MTcwOTIzODY3MDI3MDYxMzU2MDg4NzY5OTM1Mjk0NDk5NjU1MDI5NSJdfQ`

	schemaLoader := &mockJSONLDSchemaLoader{schema: kycV4Schema}
	authInstance, err := NewVerifier(verificationKeyloader, schemaLoader, stateResolvers)
	require.NoError(t, err)
	_, err = authInstance.FullVerify(context.Background(), token, request)
	require.NoError(t, err)
}

func TestEmptyCredentialSubject(t *testing.T) {
	// request
	verifierID := "did:polygonid:polygon:mumbai:2qEevY9VnKdNsVDdXRv3qSLHRqoMGMRRdE5Gmc6iA7"
	callbackURL := "https://test.com/callback"
	reason := "age verification"

	var mtpProofRequest protocol.ZeroKnowledgeProofRequest
	mtpProofRequest.ID = 1
	mtpProofRequest.CircuitID = string(circuits.AtomicQuerySigV2CircuitID)
	opt := true
	mtpProofRequest.Optional = &opt
	mtpProofRequest.Query = map[string]interface{}{
		"allowedIssuers": []string{"*"},
		"context":        "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v101.json-ld",
		"type":           "KYCEmployee",
	}
	request := CreateAuthorizationRequestWithMessage(reason, "", verifierID, callbackURL)
	request.Body.Scope = append(request.Body.Scope, mtpProofRequest)
	request.ID = "28494007-9c49-4f1a-9694-7700c08865bf"
	request.ThreadID = "ee92ab12-2671-457e-aa5e-8158c205a985" // because it's used in the response

	token := `eyJhbGciOiJncm90aDE2IiwiY2lyY3VpdElkIjoiYXV0aFYyIiwiY3JpdCI6WyJjaXJjdWl0SWQiXSwidHlwIjoiYXBwbGljYXRpb24vaWRlbjMtemtwLWpzb24ifQ.eyJpZCI6Ijc0MWU2MTA4LTM4MzgtNDFiYS1hMGIwLTlhZmZkZjY1NTg2YSIsInR5cCI6ImFwcGxpY2F0aW9uL2lkZW4zY29tbS1wbGFpbi1qc29uIiwidHlwZSI6Imh0dHBzOi8vaWRlbjMtY29tbXVuaWNhdGlvbi5pby9hdXRob3JpemF0aW9uLzEuMC9yZXNwb25zZSIsInRoaWQiOiIxNjEwN2QwYi01ZDU3LTQ1OWEtYWJiMi00OWE2Mjg2YTA5NTMiLCJmcm9tIjoiZGlkOnBvbHlnb25pZDpwb2x5Z29uOm11bWJhaToycUd5VDhtTUdydlRqTVdDelRHOE1YVG9neGp6UFRVYjJMa2tMM0FKMTEiLCJ0byI6ImRpZDpwb2x5Z29uaWQ6cG9seWdvbjptdW1iYWk6MnFKNjg5a3BvSnhjU3pCNXNBRkp0UHNTQlNySEY1ZHE3MjJCSE1xVVJMIiwiYm9keSI6eyJkaWRfZG9jIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy9ucy9kaWQvdjEiXSwiaWQiOiJkaWQ6cG9seWdvbmlkOnBvbHlnb246bXVtYmFpOjJxR3lUOG1NR3J2VGpNV0N6VEc4TVhUb2d4anpQVFViMkxra0wzQUoxMSIsInNlcnZpY2UiOlt7ImlkIjoiZGlkOnBvbHlnb25pZDpwb2x5Z29uOm11bWJhaToycUd5VDhtTUdydlRqTVdDelRHOE1YVG9neGp6UFRVYjJMa2tMM0FKMTEjcHVzaCIsInR5cGUiOiJwdXNoLW5vdGlmaWNhdGlvbiIsInNlcnZpY2VFbmRwb2ludCI6Imh0dHBzOi8vcHVzaC1zdGFnaW5nLnBvbHlnb25pZC5jb20vYXBpL3YxIiwibWV0YWRhdGEiOnsiZGV2aWNlcyI6W3siY2lwaGVydGV4dCI6IkMxRU9BNGViOUh6RC9QREtPeHlaazZaYjBaUzlvSlR1RmgyTi8xaTJ3TWxrdFJ4bzhteGJmMnN2Nk14OFl1SGRLbVo4eVJWbE9CSmpqOGRDckxDRHplYjJPREs2ZDVsanN0S05GTUlhOFh6aW1DV2I5eXoyN0h6Tm1EbTJWdGtJQWxaSjB6cEJFdnZlSWNUVVVodmNXeFkzQnVRRnpYdmJHL2lIYnUxcWRkdUh3L3JVMmJoTE9jdDN1bnpXVnB3T1pVYXg5TExTWk9zSGVyR0hZM1JJWUp5ZCtDcVV3TU5DQWJHYlJFcjlUU1pGdU1HbzZ1NGVRSlBOOURGQ09NaXdCdS9UOW5vMTNCZ1NIcDhHSlV6eFc1YTg4Z0FXQUZjVE5hSDVkOUdoamlERXp4NDUyV291Wms0Zloxd1BVd3lPUHJsaCt2QjVDd05jejRpWXNZK0ZPZEFMdDdyRUZ1RWhLZXhCVlp5VmYxckFLUDhOdi83YWtHdCtaWlZJY3RsRHRTUGUwYXpseW9TYTFKVVo2a0JLclJWdmUvL1pWdVRSMm81VHRXN2I2SlJVZ2w2S2IrVEhiN3V1OWlRcDN5ODAvWTVtMXpiSzNyUnlLTjM0U0YwMmpkY2JkZWVoeWNRc1NTMmRscm1oODZ6MWRvUS9XMVlXQ0Zzam1PazNQdnZxVU8rSXRPSnhVYURNcWVlZXE2QldldUxxd01oZE5KRVRBN3BIRzhES1JFdDZZLzNXRlNaOFF0aWdVWU9XQUplVXNHRzh1SFRSeSt3aVVKV1NIcVFTSmZHdXFOakFLa05mVFVYeDNqWmhOYmEveEFtUXV0bkxQQjJpbXowNHNSRFhTUzNYMUFmSnVSdUp6Wk1lTUE3MXM2TEZaS01Iakw4cXBENzI0L21OcEVFPSIsImFsZyI6IlJTQS1PQUVQLTUxMiJ9XX19XX0sIm1lc3NhZ2UiOm51bGwsInNjb3BlIjpbeyJpZCI6MSwiY2lyY3VpdElkIjoiY3JlZGVudGlhbEF0b21pY1F1ZXJ5U2lnVjIiLCJwcm9vZiI6eyJwaV9hIjpbIjE4MjgxMDIzOTY3MTY3MTQ4Mjg0MDc3ODUyNzI1MjU0MzY3MjM3MTQ5Mzc4MDY0MjY1ODIyMDc2OTM3MDQ0NDc5NDE2OTM1NDk1MDE1IiwiMTY0NzkyMzExMjExNDA2NjU4MDc0MTMzOTI1NTIzNzEzMjAxNjcxNTcwOTc5MTIxNjU4NjE5MDk0MDYwNzkzMjYzOTUyOTM5OTUwODIiLCIxIl0sInBpX2IiOltbIjEwOTE5MzU4Njg1NTY1NzQzODkzMzg3Mjk1NjgwNzk0OTY2Njg0OTQ0NjQ1ODQ3OTMyNzI4MDEzMzI1OTgxOTY5MjY4ODk1MTkxMDI2IiwiMjEwMzk4NDgwMTE3Mzc1OTUxMDM0NjYxODQ4MTIyMzI5MDk1NDE4MTAwNDY5NzE4OTY1NjE3ODAwMzg3ODMzODk0NjA2MzkxNTQ5MTMiXSxbIjI1NDUyMzEzNzU3NDU3MDM4OTY0Mzg4NjU4ODEwNjYwMjYzMTg2NzM4NTc4MzQyNDIzNDg0MDc4OTYzMzg4MDE3MjI3MjA3NDIzNzgiLCIxNzE1NTc4OTMxNzg4MDI3MDc3NzUyMDM2OTc1MDM3NzAyODk1NDA1MTQ2OTY2Mzk1MTczMDQxMTkyMzE0NDIwODc4NDQ5MzgyNzYxMSJdLFsiMSIsIjAiXV0sInBpX2MiOlsiNDYxODI0NjU0NzkwMjkzMDE3MTYwMTM5MTUyOTAxNzk5OTMyNjcyOTkyMzUyNzA1MDE4NTAwNTE2OTI5NjUxOTI3NDQ4NTA2OTQ5OCIsIjgyMDg2Njc2OTM0Njg1OTQyMzczMTU2OTY3NjQ2Njg5NTI3MzE3MDk3MjA4Nzc5OTAxMjUyNTgzNDU2MDMwMzIyNjc0NjUzMTQ4MzkiLCIxIl0sInByb3RvY29sIjoiZ3JvdGgxNiIsImN1cnZlIjoiYm4xMjgifSwicHViX3NpZ25hbHMiOlsiMSIsIjIxNDA0MDQxODQxNjkwMTMwOTA4NTk1NTI1NjA1Njk1NjY0OTY4NTAwODc3NjE3MDU2MDY0MjY5MTkyODk1NTQxNTU3NzkzMjgyIiwiMTQxNzI3NzAwODg2MDIyNTU4MjU3MzM2MTEzNjUzOTg3MTg5MzUzNzEyNDQ1NzUyNTMwNTYzNjEzMDc4MjMzMDMwMjg0NDI5MDc5NTAiLCIxIiwiMjc3NTI3NjY4MjMzNzE0NzE0MDgyNDgyMjU3MDg2ODEzMTM3NjQ4NjYyMzE2NTUxODczNjYwNzE4ODEwNzA5MTg5ODQ0NzEwNDIiLCIxIiwiNjczMjk4MjYxNjY0NzgxMTc1NDExOTc5NjE4NjQ3NDI2MTQxNzgxOTM3MDI3NzE4NzI3OTkzMzQ2OTM2MDY0NTE0OTM5NzkzNjAzMiIsIjE2ODIzMzU0OTMiLCIyMTk1Nzg2MTcwNjQ1NDAwMTYyMzQxNjE2NDAzNzU3NTU4NjU0MTIiLCIwIiwiNDc5MjEzMDA3OTQ2MjY4MTE2NTQyODUxMTIwMTI1MzIzNTg1MDAxNTY0ODM1Mjg4MzI0MDU3NzMxNTAyNjQ3Nzc4MDQ5MzExMDY3NSIsIjAiLCIxIiwiNjIyMjQ4NzU0NTgyMTgxMjYxOTMwNTEzNjkwMTc5MDI1MTc3MDM5MDY4NDEwNTI4MTkxNTcxODk5NTY4MjQ5MTkzNzA0MTc1ODc2IiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIl19XX19.eyJwcm9vZiI6eyJwaV9hIjpbIjc3NjY1ODUzMDg2MjIxMTI5MDQ1MzQ0NjQ2MDY4NTg2NDk2MzUyNTA2MzY5NDQ5NTU0MjQzMTE0MDUzODc0NjkxMDk0MDIzMzM3NTkiLCI1OTc2MDc4NDg2NzExMTUzOTk2OTYzMDQ0NDU5NjY5MzcyNjgwMTgwMjQwNDk4MTgwOTI0ODE3MjE3MTM5NjE4MzMwMDQwMTc0MTIiLCIxIl0sInBpX2IiOltbIjEyMzg2MjU2MTc1Njk4NjIwMTY5ODAxMTMwNDEyNzEyNzgwOTYyNjIwNjY5NzIxNzc1NDcyODQ4OTY2NzEwNzI1MjQ3NjczNDk0NzExIiwiOTk3NTE0NzcyMDc3ODgzNjc1MTE4NDUzMzM0ODUzMDgyMTQ0OTk3MjM4NTUzOTE4NTk0MDUxNTg4Nzk1ODgyMjczMzg1ODQ4Nzk4MCJdLFsiMzI2Njg2MDAwNjYwNzg5ODg1MzQ4NjE3OTg1NTQ4OTA3NDc4Nzg5NjQ2NjQ1ODgyNTM1ODI2OTUxMjAxNTA5MjY3OTEwMzU5NjIwNiIsIjEwMjg0MTc1Nzg2ODM3MTg4MzEzMTQ3ODY5MzY2NTU1MDU1NTMzMDU5NjI4OTUwMDI0ODk5OTAwNzQwNDM4ODYwMTU1ODYxMTM4MjAiXSxbIjEiLCIwIl1dLCJwaV9jIjpbIjEyMDg2ODY2OTk3NjY3NDIwMDg1MDIxNTkwODY4NTA3NjYzNjk3OTQwMjA2MTk1NzQyOTIxNjM1MjI0MzAwODIyMjAzMjkxNTU1NjgyIiwiODM5ODExNDQ3NjE2OTc0NDYyODgzODA0NTE2NDk0NzkxNDA4MDUzOTQ2NjQwNTU5MDU0NzY4NTgyMzI3NzgxMzc3ODk0NDE2ODA1OCIsIjEiXSwicHJvdG9jb2wiOiJncm90aDE2IiwiY3VydmUiOiJibjEyOCJ9LCJwdWJfc2lnbmFscyI6WyIyMTQwNDA0MTg0MTY5MDEzMDkwODU5NTUyNTYwNTY5NTY2NDk2ODUwMDg3NzYxNzA1NjA2NDI2OTE5Mjg5NTU0MTU1Nzc5MzI4MiIsIjIwOTQ1MjY4MTg3NDg3NzkzMjI5NDU5NDkwMTk1MzIzMzk3NzY2ODIzNjQwNTU1ODU0NjMxNDI2NDE0MTgyOTU4NDk2Mjg3MTUwMDY4IiwiMTA1MjI5NTY0NzMwODM3MjU4OTA1Nzk2ODUxMjM2NzgyNTYxNzQ5MTMyOTY0MTI5MTIzMDE0MzU0NTIwNjAyOTQ2ODI1MTEzODU0NzMiXX0`

	schemaLoader := &mockJSONLDSchemaLoader{schema: kycV101Schema}
	authInstance, err := NewVerifier(verificationKeyloader, schemaLoader, stateResolvers)
	require.NoError(t, err)
	_, err = authInstance.FullVerify(context.Background(), token, request)
	require.NoError(t, err)
}
