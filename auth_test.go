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
)

var verificationKeyloader = &loaders.FSKeyLoader{Dir: "./testdata"}
var schemaLoader = &mockMemorySchemaLoader{}

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
        "@id": "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc.json-ld#KYCAgeCredential",
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
        "@id": "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc.json-ld#KYCCountryOfResidenceCredential",
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
}
`), "json-ld", nil
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
	verifierID := "1125GJqgw6YEsKFwj63GY87MMxPL9kwDKxPUiwMToR"
	callbackURL := "https://test.com/callback"
	reason := "test"

	var mtpProofRequest protocol.ZeroKnowledgeProofRequest
	mtpProofRequest.ID = 10
	mtpProofRequest.CircuitID = string(circuits.AtomicQuerySigV2CircuitID)
	opt := true
	mtpProofRequest.Optional = &opt
	mtpProofRequest.Query = map[string]interface{}{
		"allowedIssuers": []string{"*"},
		"credentialSubject": map[string]interface{}{
			"documentType": map[string]interface{}{
				"$eq": 2,
			},
		},
		"context": "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
		"type":    "KYCAgeCredential",
	}
	request := CreateAuthorizationRequestWithMessage(reason, "message to sign", verifierID, callbackURL)
	request.Body.Scope = append(request.Body.Scope, mtpProofRequest)

	userID := "did:polygonid:polygon:mumbai:2qPy2CHhCfXdZcQGZAQVtsgdfR5BghueMYBbeh3vEu"
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
				ID:        10,
				CircuitID: mtpProofRequest.CircuitID,
				ZKProof: types.ZKProof{
					Proof: &types.ProofData{
						A: []string{
							"9389088925084362941182847197191684819148768623682376516852007431947991724989",
							"10568259185686785381482458779260308393741768509936906972837778621156057089175",
							"1",
						},
						B: [][]string{
							{
								"18124518804005049977040972239644901379850438882307354898206467796069627773948",
								"20337465054461875016981540168126209362569486189420367572442053617649167439202",
							},
							{
								"1123201787975741753421527461074128184903399365080547359104572298983368672215",
								"4548444000521702193082320071242238613966357808459869880760834322961625467904",
							},
							{
								"1",
								"0",
							}},
						C: []string{
							"21413255921749477147380863320680340935992194551925147727466515372811521631932",
							"17996692242791045240315166989962741859942785648600151787186333244524731532834",
							"1",
						},
						Protocol: "groth16",
					},
					PubSignals: []string{
						"1",
						"18463205224409045257121573279869541972513923822404277784072747464647315970",
						"19957126849313370387584567286711121936986032218550948293907888124760980319382",
						"10",
						"23549948072705994376874672497327914995985875946961888995821665795035566594",
						"1",
						"19957126849313370387584567286711121936986032218550948293907888124760980319382",
						"1671536992",
						"74977327600848231385663280181476307657",
						"0",
						"17040667407194471738958340146498954457187839778402591036538781364266841966",
						"0",
						"1",
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
					},
				},
			},
		},
	}

	authInstance := NewVerifier(verificationKeyloader, schemaLoader, stateResolvers)
	err := authInstance.VerifyAuthResponse(context.Background(), message, request)
	require.Nil(t, err)
}

func TestVerifyMessageWithMTPProof_Merkalized(t *testing.T) {
	verifierID := "1125GJqgw6YEsKFwj63GY87MMxPL9kwDKxPUiwMToR"
	callbackURL := "https://test.com/callback"
	reason := "test"

	var mtpProofRequest protocol.ZeroKnowledgeProofRequest
	mtpProofRequest.ID = 10
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

	userID := "did:polygonid:polygon:mumbai:2qNAbfxams2N4enwgBhj7yvPUbDrLwC2bsBZYZCTQR"
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
				ID:        10,
				CircuitID: mtpProofRequest.CircuitID,
				ZKProof: types.ZKProof{
					Proof: &types.ProofData{
						A: []string{
							"9517112492422486418344671523752691163637612305590571624363668885796911150333",
							"8855938450276251202387073646943136306720422603123854769235151758541434807968",
							"1",
						},
						B: [][]string{
							{
								"18880568320884466923930564925565727939067628655227999252296084923782755860476",
								"8724893415197458543695192455798597402395044930214471497778888748319129905479",
							},
							{
								"9807559381041464075347519433137353143151890330916363861193891037865993320923",
								"6995202980453256069532771522391679223085808426805857698209331232672383046019",
							},
							{
								"1",
								"0",
							}},
						C: []string{
							"16453660244095377174525331937765624986258178472608723119429308977591704509298",
							"7523187725705152586426891868747265746542072544935310991409893207335385519512",
							"1",
						},
						Protocol: "groth16",
					},
					PubSignals: []string{
						"1",
						"25054465935916343733470065977393556898165832783214621882239050035846517250",
						"10",
						"25054465935916343733470065977393556898165832783214621882239050035846517250",
						"7120485770008490579908343167068999806468056401802904713650068500000641772574",
						"1",
						"7120485770008490579908343167068999806468056401802904713650068500000641772574",
						"1671543597",
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
	require.Nil(t, err)
}

func TestVerifier_VerifyJWZ(t *testing.T) {

	token := ` eyJhbGciOiJncm90aDE2IiwiY2lyY3VpdElkIjoiYXV0aFYyIiwiY3JpdCI6WyJjaXJjdWl0SWQiXSwidHlwIjoiSldaIn0.bWVzc2FnZQ.eyJwcm9vZiI6eyJwaV9hIjpbIjE2Njg0NTgxNTM5NDI0MjgzMjc5NjAxMzg1MjE5Mzc0MjkzNjQ5MDg5OTgzNjMyNzg1NTk4OTc1ODkxMzM2Njg4NzEzNjc5ODYyNTgzIiwiMTAzNjU5ODAzMDYzMzYyOTUxMDkwNDQ0OTUxNTkwMjIzOTkyMzMwNjU5NzU4MjMzMTk3NTc5MDMwMjQ3ODczNTIxMzE4OTkzODQzMDEiLCIxIl0sInBpX2IiOltbIjQ4MjM0OTk3NTQ0NTk4MjQ2NjM4NTA4NjE0NjgzNzU1MjM2NDc3NzgxNDgwMzI3NDIwNzM2NTA1NTA0MjM4NjU0OTU2NDI1MDMwMTYiLCIxNzUxMDQ5NzY1MzMyODk2MjM5Nzk2NDkwNDczNTAyOTU4ODIxOTQyMjU2NzY2MjMyNDU5OTQ5Mjg4NzMwMTQ4NjAyNjkwNDM3MDc0NSJdLFsiNjYzMzg3NTY3NzY5Mzc2MTQ2MDM0ODIzNTM2OTIxNDgwMTkwNjUyNjg3OTI4MTg2MDY4NDQ0ODA4MzYxMTIwMjA2MjA1MDc1NzUzMSIsIjg3NTgwNzE3MDUwNjUzNTQ0OTY3Mzc5NzAzODY5ODMyNTA2Nzg4OTc4Mjc3NjMxODkxODc4ODk4NDAyMjgxNDE3NTg4MjMwNTE1MjIiXSxbIjEiLCIwIl1dLCJwaV9jIjpbIjExMDg0NjQ4MzIyNzc1MTMyOTEwNTI0MTE4Mjg0ODgwOTI3MTk3MjE0NjgwMjU3MTU5NDA0MzU5MDQ0MDM0MTAzMTAyMDYzMDEzMTc3IiwiMzY2NjExNjkxODg0MDMzMDU5MzA5MjcyNjI2ODY0NjMzNjczMjY2MTY0MjI3NjE3NDc0NzczMzk1NjU3MjA1NjgzNDQ3MjYzNDYxNSIsIjEiXSwicHJvdG9jb2wiOiJncm90aDE2In0sInB1Yl9zaWduYWxzIjpbIjI1MDU0NDY1OTM1OTE2MzQzNzMzNDcwMDY1OTc3MzkzNTU2ODk4MTY1ODMyNzgzMjE0NjIxODgyMjM5MDUwMDM1ODQ2NTE3MjUwIiwiMTA0NTczNjMzMTkwMjQ4MTQ0NjY5NDQyNjYxMTE5MTc1ODkyNTgzOTE2MzczNDM0OTA5MTM0MTM5NjUxMzcwMzIxNzg3MTg0MDgxMTYiLCI1MzA0Njg1OTQ1NTI0MTc3MjA4MzQ5NDczNzc3MjMzOTcwNjk2NTU1ODA0NzQwNzM2MTU4NjA2ODI1MTE2ODA2MDgwMDU0NjA0Mzg1Il19 `

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
	mtpProofRequest.ID = 10
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
	request.ID = "28494007-9c49-4f1a-9694-7700c08865bf"
	request.ThreadID = "ee92ab12-2671-457e-aa5e-8158c205a985" // because it's used in the response

	token := ` eyJhbGciOiJncm90aDE2IiwiY2lyY3VpdElkIjoiYXV0aFYyIiwiY3JpdCI6WyJjaXJjdWl0SWQiXSwidHlwIjoiSldaIn0.eyJpZCI6IjI3NGI1ODE5LWMxNDctNGExNy1iNGUxLTRmZDJhOWNmNTdhNSIsInR5cCI6ImFwcGxpY2F0aW9uL2lkZW4zY29tbS1wbGFpbi1qc29uIiwidHlwZSI6Imh0dHBzOi8vaWRlbjMtY29tbXVuaWNhdGlvbi5pby9hdXRob3JpemF0aW9uLzEuMC9yZXNwb25zZSIsInRoaWQiOiI4NWFjMjc3Yi0xYWZlLTQzY2EtYWNmZC1mOTM5ZTAwODBkZDYiLCJib2R5Ijp7Im1lc3NhZ2UiOiJtZXNzYWdlIHRvIHNpZ24iLCJzY29wZSI6W3siaWQiOjEwLCJjaXJjdWl0SWQiOiJjcmVkZW50aWFsQXRvbWljUXVlcnlNVFBWMiIsInByb29mIjp7InBpX2EiOlsiOTUxNzExMjQ5MjQyMjQ4NjQxODM0NDY3MTUyMzc1MjY5MTE2MzYzNzYxMjMwNTU5MDU3MTYyNDM2MzY2ODg4NTc5NjkxMTE1MDMzMyIsIjg4NTU5Mzg0NTAyNzYyNTEyMDIzODcwNzM2NDY5NDMxMzYzMDY3MjA0MjI2MDMxMjM4NTQ3NjkyMzUxNTE3NTg1NDE0MzQ4MDc5NjgiLCIxIl0sInBpX2IiOltbIjE4ODgwNTY4MzIwODg0NDY2OTIzOTMwNTY0OTI1NTY1NzI3OTM5MDY3NjI4NjU1MjI3OTk5MjUyMjk2MDg0OTIzNzgyNzU1ODYwNDc2IiwiODcyNDg5MzQxNTE5NzQ1ODU0MzY5NTE5MjQ1NTc5ODU5NzQwMjM5NTA0NDkzMDIxNDQ3MTQ5Nzc3ODg4ODc0ODMxOTEyOTkwNTQ3OSJdLFsiOTgwNzU1OTM4MTA0MTQ2NDA3NTM0NzUxOTQzMzEzNzM1MzE0MzE1MTg5MDMzMDkxNjM2Mzg2MTE5Mzg5MTAzNzg2NTk5MzMyMDkyMyIsIjY5OTUyMDI5ODA0NTMyNTYwNjk1MzI3NzE1MjIzOTE2NzkyMjMwODU4MDg0MjY4MDU4NTc2OTgyMDkzMzEyMzI2NzIzODMwNDYwMTkiXSxbIjEiLCIwIl1dLCJwaV9jIjpbIjE2NDUzNjYwMjQ0MDk1Mzc3MTc0NTI1MzMxOTM3NzY1NjI0OTg2MjU4MTc4NDcyNjA4NzIzMTE5NDI5MzA4OTc3NTkxNzA0NTA5Mjk4IiwiNzUyMzE4NzcyNTcwNTE1MjU4NjQyNjg5MTg2ODc0NzI2NTc0NjU0MjA3MjU0NDkzNTMxMDk5MTQwOTg5MzIwNzMzNTM4NTUxOTUxMiIsIjEiXSwicHJvdG9jb2wiOiJncm90aDE2In0sInB1Yl9zaWduYWxzIjpbIjEiLCIyNTA1NDQ2NTkzNTkxNjM0MzczMzQ3MDA2NTk3NzM5MzU1Njg5ODE2NTgzMjc4MzIxNDYyMTg4MjIzOTA1MDAzNTg0NjUxNzI1MCIsIjEwIiwiMjUwNTQ0NjU5MzU5MTYzNDM3MzM0NzAwNjU5NzczOTM1NTY4OTgxNjU4MzI3ODMyMTQ2MjE4ODIyMzkwNTAwMzU4NDY1MTcyNTAiLCI3MTIwNDg1NzcwMDA4NDkwNTc5OTA4MzQzMTY3MDY4OTk5ODA2NDY4MDU2NDAxODAyOTA0NzEzNjUwMDY4NTAwMDAwNjQxNzcyNTc0IiwiMSIsIjcxMjA0ODU3NzAwMDg0OTA1Nzk5MDgzNDMxNjcwNjg5OTk4MDY0NjgwNTY0MDE4MDI5MDQ3MTM2NTAwNjg1MDAwMDA2NDE3NzI1NzQiLCIxNjcxNTQzNTk3IiwiMzM2NjE1NDIzOTAwOTE5NDY0MTkzMDc1NTkyODUwNDgzNzA0NjAwIiwiMCIsIjE3MDAyNDM3MTE5NDM0NjE4NzgzNTQ1Njk0NjMzMDM4NTM3MzgwNzI2MzM5OTk0MjQ0Njg0MzQ4OTEzODQ0OTIzNDIyNDcwODA2ODQ0IiwiMCIsIjUiLCI4NDAiLCIxMjAiLCIzNDAiLCI1MDkiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiXX1dfSwiZnJvbSI6ImRpZDpwb2x5Z29uaWQ6cG9seWdvbjptdW1iYWk6MnFOQWJmeGFtczJONGVud2dCaGo3eXZQVWJEckx3QzJic0JaWVpDVFFSIiwidG8iOiIxMTI1R0pxZ3c2WUVzS0Z3ajYzR1k4N01NeFBMOWt3REt4UFVpd01Ub1IifQ.eyJwcm9vZiI6eyJwaV9hIjpbIjgwMzM1NzQwMzc0MjEyOTIxMDY4Mzk5MjkwMTg5ODA4MzcxMDM3NTY2NTA4MTkyMTgzNjgzODYyOTAxNTY1MzY0MTIyNTY5MjQwOTUiLCI1MjA2ODkzODk0MTg2ODE1Mjg1MzIyNjQ3MDUwOTkyNDk0ODQwNzc1MDUwMTM2MzgwMjYyMjM2MTkyNTIwNzQ2ODY1OTA3OTczNDIyIiwiMSJdLCJwaV9iIjpbWyIyMTQzNzU0OTcxNTU3NzA2MzkzNDM3NTM3ODcyMDQwMzIxMzIzNDExODM5MDQ3NjQyMzI3MDY2NTQxNzUwMDA3ODU2ODg2NDE1NzIzOCIsIjY5MTQ0MjkxMTM0ODEwMDQyODYwODcxOTc3MTI4NjgzNjIzMTcwMTQyMTk2MjA3NDg0NjQ4OTgyMjI1MDU2NjA5MzgyMjQ4NDk4MDciXSxbIjEyMzUwMDk4MjEzMjk2OTM4NTM3Mzk0NTEwODQ0MzAyODM3NTk4MTUyOTQ1NTA5NzExNzk2OTg4MzM0MjAzOTY2NzU2MzY2OTQ1NTA4IiwiMjcwOTE5NDc5NjcyNTEzMzA1ODM4Mzc5MTczMjM2NDIxMjA3MTkyNDg2MTQxMjIyOTU4NjUzNTk3Njc1NTc1MjM4NzQyNjUyNzg0MyJdLFsiMSIsIjAiXV0sInBpX2MiOlsiMTkwMTQ3MzM1MTgwNTE1Nzg1MDk3Nzc4MzQ0ODEwMjg3NzkzODc1NDI0NjAwMjE5MzI3OTk1MTUxNzY4Mzk1NzE2MDI5MDU0ODQyNTIiLCIyMTUwNDg1MzA5MDQ0MTc3MDMzMzA2NDI4NDk3MjY1MDE3NDI2OTc5MjA3OTg1MTY1Mzk3NzczMjc0MjcyMDY2ODExNDAwMjk1OTQ5MCIsIjEiXSwicHJvdG9jb2wiOiJncm90aDE2In0sInB1Yl9zaWduYWxzIjpbIjI1MDU0NDY1OTM1OTE2MzQzNzMzNDcwMDY1OTc3MzkzNTU2ODk4MTY1ODMyNzgzMjE0NjIxODgyMjM5MDUwMDM1ODQ2NTE3MjUwIiwiODE4ODQ4NTI3MDk2MTY2NzYwMTc3MjQ5OTE2ODMwNzU2MDEyNDYxNzM5MjE3NzcxODQyODUxODg3NjgyNjU4MjAzNzk0NjU4MzI2NCIsIjUzMDQ2ODU5NDU1MjQxNzcyMDgzNDk0NzM3NzcyMzM5NzA2OTY1NTU4MDQ3NDA3MzYxNTg2MDY4MjUxMTY4MDYwODAwNTQ2MDQzODUiXX0`

	authInstance := NewVerifier(verificationKeyloader, schemaLoader, stateResolvers)
	_, err := authInstance.FullVerify(context.Background(), token, request)
	assert.Nil(t, err)

}

func TestVerifyAuthResponseWithEmptyReq_ErrorCase(t *testing.T) {

	verifierID := "1125GJqgw6YEsKFwj63GY87MMxPL9kwDKxPUiwMLNZ"
	callbackURL := "https://test.com/callback"
	reason := "test"

	userID := "did:polygonid:polygon:mumbai:2qNAbfxams2N4enwgBhj7yvPUbDrLwC2bsBZYZCTQR"
	var zkReq protocol.ZeroKnowledgeProofRequest
	zkReq.ID = 10
	zkReq.CircuitID = string(circuits.AtomicQueryMTPV2CircuitID)
	opt := true
	zkReq.Optional = &opt
	zkReq.Query = map[string]interface{}{
		"allowedIssuers": []string{"*"},
		"context":        "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
		"type":           "KYCCountryOfResidenceCredential",
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
					ID:        10,
					CircuitID: string(circuits.AtomicQueryMTPV2CircuitID),
					ZKProof: types.ZKProof{
						Proof: &types.ProofData{
							A: []string{
								"9517112492422486418344671523752691163637612305590571624363668885796911150333",
								"8855938450276251202387073646943136306720422603123854769235151758541434807968",
								"1",
							},
							B: [][]string{
								{
									"18880568320884466923930564925565727939067628655227999252296084923782755860476",
									"8724893415197458543695192455798597402395044930214471497778888748319129905479",
								},
								{
									"9807559381041464075347519433137353143151890330916363861193891037865993320923",
									"6995202980453256069532771522391679223085808426805857698209331232672383046019",
								},
								{
									"1",
									"0",
								}},
							C: []string{
								"16453660244095377174525331937765624986258178472608723119429308977591704509298",
								"7523187725705152586426891868747265746542072544935310991409893207335385519512",
								"1",
							},
							Protocol: "groth16",
						},
						PubSignals: []string{
							"1",
							"25054465935916343733470065977393556898165832783214621882239050035846517250",
							"10",
							"25054465935916343733470065977393556898165832783214621882239050035846517250",
							"7120485770008490579908343167068999806468056401802904713650068500000641772574",
							"1",
							"7120485770008490579908343167068999806468056401802904713650068500000641772574",
							"1671543597",
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
		},
		From: userID,
		To:   authReq.From,
	}

	authInstance := NewVerifier(verificationKeyloader, schemaLoader, stateResolvers)
	err := authInstance.VerifyAuthResponse(context.Background(), resp, authReq)
	assert.ErrorIs(t, err, pubsignals.ErrRequestOperator)
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
