package auth

import (
	"context"
	"math/big"
	"testing"

	"github.com/google/uuid"
	"github.com/iden3/go-circuits"
	"github.com/iden3/go-iden3-auth/loaders"
	"github.com/iden3/go-iden3-auth/pubsignals"
	"github.com/iden3/go-iden3-auth/state"
	"github.com/iden3/go-rapidsnark/types"
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
var schemaLoader = &mockMemorySchemaLoader{}
var nonMerklizedSchemaLoader = &mockMemoryNonMerklizedSchemaLoader{}

/*
mock for schema loader
*/
type mockMemorySchemaLoader struct {
}

func (r *mockMemorySchemaLoader) Load(_ context.Context, _ string) (schema []byte, ext string, err error) {
	return []byte(`{
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
  }`), "json-ld", nil
}

type mockMemoryNonMerklizedSchemaLoader struct {
}

func (r *mockMemoryNonMerklizedSchemaLoader) Load(_ context.Context, _ string) (schema []byte, ext string, err error) {
	return []byte(`{
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
		  }`), "json-ld", nil
}

/*
mock for state resolver
*/
var stateResolvers = map[string]pubsignals.StateResolver{
	"polygon:mumbai": &mockStateResolver{},
}

type mockStateResolver struct {
}

func (r *mockStateResolver) Resolve(_ context.Context, id, s *big.Int) (*state.ResolvedState, error) {
	return &state.ResolvedState{Latest: true, Genesis: false, TransitionTimestamp: 0}, nil
}

func (r *mockStateResolver) ResolveGlobalRoot(_ context.Context, _ *big.Int) (*state.ResolvedState, error) {
	return &state.ResolvedState{Latest: true, TransitionTimestamp: 0}, nil
}

func TestVerifyMessageWithSigProof_NonMerkalized(t *testing.T) {
	// TODO(illia-korotia): for non merklized claim and schema don't know about xsd:types
	t.Skip("skipping test")
	verifierID := "1125GJqgw6YEsKFwj63GY87MMxPL9kwDKxPUiwMToR"
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

	authInstance := NewVerifier(verificationKeyloader, nonMerklizedSchemaLoader, stateResolvers)
	err := authInstance.VerifyAuthResponse(context.Background(), message, request)
	require.Nil(t, err)
}

func TestVerifyMessageWithMTPProof_Merkalized(t *testing.T) {
	verifierID := "1125GJqgw6YEsKFwj63GY87MMxPL9kwDKxPUiwMToR"
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

	authInstance := NewVerifier(verificationKeyloader, schemaLoader, stateResolvers)
	err := authInstance.VerifyAuthResponse(context.Background(), message, request)
	require.NoError(t, err)
}

func TestVerifier_VerifyJWZ(t *testing.T) {

	token := `eyJhbGciOiJncm90aDE2IiwiY2lyY3VpdElkIjoiYXV0aFYyIiwiY3JpdCI6WyJjaXJjdWl0SWQiXSwidHlwIjoiYXBwbGljYXRpb24vaWRlbjMtemtwLWpzb24ifQ.eyJpZCI6IjljMGY5NjIzLWM1NmMtNDEwNC04ODk2LWVjMjgyYTNiMmExNyIsInR5cCI6ImFwcGxpY2F0aW9uL2lkZW4zY29tbS1wbGFpbi1qc29uIiwidHlwZSI6Imh0dHBzOi8vaWRlbjMtY29tbXVuaWNhdGlvbi5pby9hdXRob3JpemF0aW9uLzEuMC9yZXNwb25zZSIsInRoaWQiOiI3ZjM4YTE5My0wOTE4LTRhNDgtOWZhYy0zNmFkZmRiOGI1NDIiLCJmcm9tIjoiZGlkOnBvbHlnb25pZDpwb2x5Z29uOm11bWJhaToycVBETFhEYVUxeGExRVJUYjFYS0JmUENCM28yd0E0NnE0OW5laVhXd1kiLCJ0byI6ImRpZDpwb2x5Z29uaWQ6cG9seWdvbjptdW1iYWk6MnFKNjg5a3BvSnhjU3pCNXNBRkp0UHNTQlNySEY1ZHE3MjJCSE1xVVJMIiwiYm9keSI6eyJkaWRfZG9jIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy9ucy9kaWQvdjEiXSwiaWQiOiJkaWQ6cG9seWdvbmlkOnBvbHlnb246bXVtYmFpOjJxUERMWERhVTF4YTFFUlRiMVhLQmZQQ0IzbzJ3QTQ2cTQ5bmVpWFd3WSIsInNlcnZpY2UiOlt7ImlkIjoiZGlkOnBvbHlnb25pZDpwb2x5Z29uOm11bWJhaToycVBETFhEYVUxeGExRVJUYjFYS0JmUENCM28yd0E0NnE0OW5laVhXd1kjcHVzaCIsInR5cGUiOiJwdXNoLW5vdGlmaWNhdGlvbiIsInNlcnZpY2VFbmRwb2ludCI6Imh0dHBzOi8vcHVzaC1zdGFnaW5nLnBvbHlnb25pZC5jb20vYXBpL3YxIiwibWV0YWRhdGEiOnsiZGV2aWNlcyI6W3siY2lwaGVydGV4dCI6InhZK3RHWHUrOWlHMHZ6dFpMTTlKN25PcDNRbE1Uci85TmI3Qjl5Q0prbDlxcUpiZ1AvMExOL1VmTkxxQUk4RWZIcFhJVlVlTmVVUmNCNm82bWVMVlpJK2VvMlhvcDM2SE1iK2JyQnJTTjRqVHZWVkRDQXVXSkI2akV5Q3ZNRzlMaXp6blBsS3VQSE15dEdCVnZnV0laRFZBeVdZbTFyMk9PUzc4OU5DZm41MnNjV0VRVW5VRWdnTmpyWjlLdFpmb09RMlBDbUpqRXpDejg0ZUc3RGM2bEFvbi8ycTJJNVlLQk12RkhnT3c4N25wb0owczVrQ1RVVENjeVRlQmg2VXpLQk5aNElibndvR3ZYcG9FelBVZXZRdjRGbXVTaExYYVF3Vk9nalRBUXR0T2g2SjZhcmE4UHNndVFGQ3dNUTlxV2JjTjZYdXlScjk4TVlqbGxpL0VEN09TZzBsWVU5cUdLa1RaL2ZZN2VWZkYyeFFhOWZXK01WVzlxM2NJMjJzbkRwV28xY1ZYNWt1TWhpbmFsajZXV1Q0OTAvblNXak1rZ3JkL25CdXNiMHR4eG1jWDU3QUowcVlyMkNsK0pQb1FhcExiOEFTT3dGYU5kRDRZV3pKWXRXVmlDbktMZ3dQNDFHaGl5NVNWZE1vbU1sUy9kSGo2TVZPMjNyOVRiTDFrRy8rdkFIZWF0YkdvZ3p1OWd3SzlJckF3WS95THhMYVpQcHZzdlJLWjVBa2E1b1pkbmRNNkdLUkM0OVhoVXloQnNlY0N2Z1hNeGZGNVBnWGhROVFTb1drMzFXSWRiWG5vbmU2YmVNQkpLUVYzemg2MmpoZUFuV3czZW16dndKajRUUHU4WTJQZ2lDL3FaZXhlUVlKdFNkelJXZUFjK2N5a2ZwTXA0SmdrV2hBPSIsImFsZyI6IlJTQS1PQUVQLTUxMiJ9XX19XX0sIm1lc3NhZ2UiOm51bGwsInNjb3BlIjpbeyJpZCI6MjMsImNpcmN1aXRJZCI6ImNyZWRlbnRpYWxBdG9taWNRdWVyeU1UUFYyIiwicHJvb2YiOnsicGlfYSI6WyIyNjEwNjg1Nzc1MTY0Mzc0MDE2MTM5NDQwNTM4NzMxODI0NTgzNjQyODg0MTQxMzA5MTQwNDgzNDU0ODMzNzcyMjYxNDQ2NTI2NTEiLCIxNDE5MTI2MDA3MTY5NTk4MDAxMTY3OTUwMTgwODQ1MzIyMjI2NzUyMDcyMTc2Nzc1Nzc1OTE1MDEwMTk3NDM4MjA1MzE2MTY3NDYxMSIsIjEiXSwicGlfYiI6W1siNzY3MDg0Nzg0NDAxNTExNjk1NzUyNjE4MzcyODE5Njk3Nzk1NzMxMjYyNzMwNzc5NzkxOTU1NDEzNDY4NDkwMTQwMTQzNjAyMTk3NyIsIjE0OTU3ODQ1NDcyNjMwMDE3MDk1ODIxODMzMjIyNTgwMTk0MDYxMjY2MTg2ODUxNjM0MDUzODk3NzY4NzM4MjUzNjYzMjUzNjUwODM1Il0sWyIxNzgzNTY0MjQ1ODQ4NDYyODYyNzU1NjMyOTg3NjkxOTA3NzMzMzkxMjAxMTIzNTMwODc1ODgzMjE3Mjg4MDAxMjgxMzM5NzAyMjEwNCIsIjE4MTAwODYxMTMwMTQ5Njc4MTUzMTMzMDI1MDMxNzA5ODk3MTIwMDk3MDk4NTkxMjk4ODE3MzY3NDkxOTIwNTUzMDM3MDExNjUwMjI4Il0sWyIxIiwiMCJdXSwicGlfYyI6WyI2MjE3ODY1OTQ5Mjk5OTkwNjQyODMyNTIzMjU2ODYzMDQ4OTMyMjEwNTQ2MDQ5MjAzMTg5MTEzMzYyODUxNDc2OTY2ODI0MTYyMTkxIiwiMTkwMTY5NDkyMjUyNzc3NTU2OTAwMTk2NDczODU4NTU5MzY5Njk5Mjg5OTQyMTA5MDU5OTI2MjgzMDE5Njc4ODM4MDM2NzA0MzY1MTAiLCIxIl0sInByb3RvY29sIjoiZ3JvdGgxNiIsImN1cnZlIjoiYm4xMjgifSwicHViX3NpZ25hbHMiOlsiMSIsIjI3MTUyNjc2OTg3MTI4NTQyMDY2ODA4NTkxOTk4NTczMDAwMzcwNDM2NDY0NzIyNTE5NTEzMzQ4ODkxMDQ5NjQ0ODEzNzE4MDE4IiwiMjMiLCIyNzc1Mjc2NjgyMzM3MTQ3MTQwODI0ODIyNTcwODY4MTMxMzc2NDg2NjIzMTY1NTE4NzM2NjA3MTg4MTA3MDkxODk4NDQ3MTA0MiIsIjIxNTQ1NzY4ODgzNTA5NjU3MzQwMjA5MTcxNTQ5NDQxMDA1NjAzMzA2MDEyNTEzOTMyMjIxMzcxNTk5NTAxNDk4NTM0ODA3NzE5Njg5IiwiMSIsIjIxNTQ1NzY4ODgzNTA5NjU3MzQwMjA5MTcxNTQ5NDQxMDA1NjAzMzA2MDEyNTEzOTMyMjIxMzcxNTk5NTAxNDk4NTM0ODA3NzE5Njg5IiwiMTY3OTMyMzAzOCIsIjMzNjYxNTQyMzkwMDkxOTQ2NDE5MzA3NTU5Mjg1MDQ4MzcwNDYwMCIsIjAiLCIxNzAwMjQzNzExOTQzNDYxODc4MzU0NTY5NDYzMzAzODUzNzM4MDcyNjMzOTk5NDI0NDY4NDM0ODkxMzg0NDkyMzQyMjQ3MDgwNjg0NCIsIjAiLCI1IiwiODQwIiwiMTIwIiwiMzQwIiwiNTA5IiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIl19XX19.eyJwcm9vZiI6eyJwaV9hIjpbIjcwMjI2MTEzODk5MzY1MDEzNDI2NTkwMjQ2Njk0NTczNTA3OTUwMTU5ODkzOTI1NzAzMDMwODQ4MzcyMTQ4MDc1MzYyNDg4NTE5MzYiLCIxMzg1OTcwODc3NTU0Mzk0Mjk3MTYxNTcxNTA1MTczNjM4MTc4NTEzODkzMjQ3ODc1Mzg3MjU5MTU0NDQxODk1ODkwOTU2MDQyOTU3NCIsIjEiXSwicGlfYiI6W1siMTE1MzQ5NjMxNDgwODQ0OTk0NDg5MDc3NzQxMTMxNjg1OTEyNDYyMjQ4OTg0MTU4ODAwMzY5NTA1MDYyMjU0ODkyMDA1NTc2NTA2NjUiLCIxNDA3MjA4Mjk1MTQ0Njc5NDk5MDk4NDcwNTE3ODA1OTY2NjI4NzM1NTEwNjc5MzUwMTg5MTE2ODgwNjE2NjUwMTUxMDkzMDY0MzQ0MSJdLFsiNDY3ODgyNDc3ODQ5ODA0NzE2OTEzNTk2NTg3MTYwNDgzNjkwMTQ1NjI5MDQ0NjQ0NjUzMzEyNzUwOTU4Mzg5MDU5MDkzNTY5ODQxNCIsIjEyODE5NzMwNTMyMDg0MTM4NDI0ODQ0MjExNDg4NjcxMTUyNDgwOTU1MzQ0MTA2NzU4NTE3NDEzODAxOTIzNTM3OTU3MzYzOTgwMjA0Il0sWyIxIiwiMCJdXSwicGlfYyI6WyIxNTUyMDYzNjk4OTY2MTg3NzExNDUwNjkwNDgxMDQxMzExNDI4NzQ5ODE1OTk2NDA5OTU2MTY5ODUyNjc4MzUwMDE1NjU1MjQzMDAwNCIsIjEyNjkyNzA3NDA3MTczMDg0OTM5NzQ1ODU5NzE0ODMxNDYyMDQ1ODg5NDA4NTk4NTI3MjU0ODA3NzkwNDk0NDY2Mjc5Njg3ODU5MjQ3IiwiMSJdLCJwcm90b2NvbCI6Imdyb3RoMTYiLCJjdXJ2ZSI6ImJuMTI4In0sInB1Yl9zaWduYWxzIjpbIjI3MTUyNjc2OTg3MTI4NTQyMDY2ODA4NTkxOTk4NTczMDAwMzcwNDM2NDY0NzIyNTE5NTEzMzQ4ODkxMDQ5NjQ0ODEzNzE4MDE4IiwiMTIxODQ5NzQwNzE0Mjc3NjgzNTIwMjcwMDM4NzgzMTkzMzgyNDkzODM4NDYxNjQ3MzAyMDQ1MDUzMjY5NTM1NTA2NDczOTExNzg4MDAiLCI4NzU2MDYwMjA1MDg2ODAzMzM1MjUyMzE5NzQ4NzQ4MzU0NzYxOTYxODE0MDEyNzI1NDk5ODczMzgyOTg4MDU2NDE4NjgwNjI4NjE5Il19`

	authInstance := NewVerifier(verificationKeyloader, schemaLoader, stateResolvers)
	parsedToken, err := authInstance.VerifyJWZ(context.Background(), token)
	require.NoError(t, err)
	require.Equal(t, parsedToken.Alg, "groth16")
}

func TestVerifier_FullVerify(t *testing.T) {
	// request
	verifierID := "1125GJqgw6YEsKFwj63GY87MMxPL9kwDKxPUiwMLNZ"
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

	authInstance := NewVerifier(verificationKeyloader, schemaLoader, stateResolvers)
	_, err := authInstance.FullVerify(context.Background(), token, request)
	require.NoError(t, err)
}

func TestVerifyAuthResponseWithEmptyReq(t *testing.T) {

	verifierID := "1125GJqgw6YEsKFwj63GY87MMxPL9kwDKxPUiwMLNZ"
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

	authInstance := NewVerifier(verificationKeyloader, nonMerklizedSchemaLoader, stateResolvers)
	err := authInstance.VerifyAuthResponse(context.Background(), resp, authReq)
	require.NoError(t, err)
}

func TestCreateAuthorizationRequest(t *testing.T) {

	sender := "1125GJqgw6YEsKFwj63GY87MMxPL9kwDKxPUiwMLNZ"
	callbackURL := "https://test.com/callback"
	reason := "basic authentication"

	request := CreateAuthorizationRequest(reason, sender, callbackURL)
	assert.Len(t, request.Body.Scope, 0)
	assert.Equal(t, callbackURL, request.Body.CallbackURL)
	assert.Equal(t, sender, request.From)
	assert.Equal(t, protocol.AuthorizationRequestMessageType, request.Type)

}

func TestCreateAuthorizationRequestWithMessage(t *testing.T) {

	sender := "1125GJqgw6YEsKFwj63GY87MMxPL9kwDKxPUiwMLNZ"
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
