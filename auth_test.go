package auth

import (
	"context"
	"math/big"
	"testing"

	"github.com/google/uuid"
	"github.com/iden3/go-iden3-auth/loaders"
	"github.com/iden3/go-iden3-auth/pubsignals"
	"github.com/iden3/go-iden3-auth/state"
	"github.com/iden3/go-rapidsnark/types"
	"github.com/iden3/iden3comm/packers"
	"github.com/iden3/iden3comm/protocol"
	"github.com/stretchr/testify/assert"

	"github.com/iden3/go-circuits"
)

var verificationKeyloader = &loaders.FSKeyLoader{Dir: "./testdata"}
var schemaLoader = &mockMemorySchemaLoader{}

/*
	mock for schema loader
*/
type mockMemorySchemaLoader struct {
}

func (r *mockMemorySchemaLoader) Load(_ context.Context, _ protocol.Schema) (schema []byte, ext string, err error) {
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
var stateResolver = &mockStateResolver{}

type mockStateResolver struct {
}

func (r *mockStateResolver) Resolve(_ context.Context, id, s *big.Int) (*state.ResolvedState, error) {
	return &state.ResolvedState{Latest: true, TransitionTimestamp: 0}, nil
}

func TestCreateAuthorizationRequest(t *testing.T) {

	sender := "1125GJqgw6YEsKFwj63GY87MMxPL9kwDKxPUiwMLNZ"
	callbackURL := "https://test.com/callback"
	reason := "basic authentication"

	request := CreateAuthorizationRequest(reason, sender, callbackURL)
	assert.Len(t, request.Body.Scope, 0)
	assert.Equal(t, callbackURL, request.Body.CallbackURL)
	assert.Equal(t, sender, request.From)

}

func TestCreateAuthorizationRequestWithZKP(t *testing.T) {

	sender := "1125GJqgw6YEsKFwj63GY87MMxPL9kwDKxPUiwMLNZ"
	callbackURL := "https://test.com/callback"
	reason := "age verification"

	var mtpProofRequest protocol.ZeroKnowledgeProofRequest

	mtpProofRequest.ID = 1
	mtpProofRequest.CircuitID = string(circuits.AtomicQueryMTPCircuitID)
	mtpProofRequest.Rules = map[string]interface{}{
		"query": pubsignals.Query{
			AllowedIssuers: []string{"*"},
			Req: map[string]interface{}{
				"$lt": "24042000",
			},
			Schema: protocol.Schema{
				URL:  "http://schema.url",
				Type: "KYCAgeCredential",
			},
		},
	}

	request := CreateAuthorizationRequest(reason, sender, callbackURL)
	request.Body.Scope = append(request.Body.Scope, mtpProofRequest)

	assert.Len(t, request.Body.Scope, 1)
	assert.Equal(t, callbackURL, request.Body.CallbackURL)
	assert.Equal(t, sender, request.From)
	assert.ObjectsAreEqual(request.Body.Scope[0], mtpProofRequest)

}

func TestVerifyMessageWithMTPProof(t *testing.T) {

	// request
	verifierID := "1125GJqgw6YEsKFwj63GY87MMxPL9kwDKxPUiwMLNZ"
	callbackURL := "https://test.com/callback"
	reason := "test"

	var mtpProofRequest protocol.ZeroKnowledgeProofRequest
	mtpProofRequest.ID = 1
	mtpProofRequest.CircuitID = string(circuits.AtomicQueryMTPCircuitID)
	opt := true
	mtpProofRequest.Optional = &opt
	mtpProofRequest.Rules = map[string]interface{}{
		"query": pubsignals.Query{
			AllowedIssuers: []string{"*"},
			Req: map[string]interface{}{
				"countryCode": map[string]interface{}{
					"$nin": []int{
						840,
						120,
						340,
						509,
					},
				},
			},
			Schema: protocol.Schema{
				URL:  "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v2.json-ld",
				Type: "KYCCountryOfResidenceCredential",
			},
		},
	}
	request := CreateAuthorizationRequestWithMessage(reason, "message to sign", verifierID, callbackURL)
	request.Body.Scope = append(request.Body.Scope, mtpProofRequest)

	userID := "119tqceWdRd2F6WnAyVuFQRFjK3WUXq2LorSPyG9LJ"
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
				ID:        1,
				CircuitID: mtpProofRequest.CircuitID,
				ZKProof: types.ZKProof{
					Proof: &types.ProofData{
						A: []string{
							"13391792855876064159961972635593293420107384528568051553464431930751949164223",
							"1340234156514424371412608292854628119646495446034903157290847790338828365967",
							"1",
						},
						B: [][]string{
							{
								"15691819979475232094559173077222615349107673259729880872754546424435804210780",
								"5096136697484789888414648180385423591377893199387718567394854201118306816266",
							},
							{
								"14415469551251600097134734841213894130439560682036739798548029076915189571196",
								"20090000223414166057341085632483118175324868197522334211992129524912673014962",
							},
							{
								"1",
								"0",
							}},
						C: []string{
							"11415503132297310226070909779026062469592946937699661170150988764296705860650",
							"10455420445628565470154609245999512669023398128793538476867561521321358405677",
							"1",
						},
						Protocol: "groth16",
					},
					PubSignals: []string{
						"379949150130214723420589610911161895495647789006649785264738141299135414272",
						"18656147546666944484453899241916469544090258810192803949522794490493271005313",
						"1",
						"17339270624307006522829587570402128825147845744601780689258033623056405933706",
						"26599707002460144379092755370384635496563807452878989192352627271768342528",
						"17339270624307006522829587570402128825147845744601780689258033623056405933706",
						"1642074362",
						"106590880073303418818490710639556704462",
						"2",
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

	authInstance := Verifier{verificationKeyloader, schemaLoader, stateResolver}
	err := authInstance.VerifyAuthResponse(context.Background(), message, request)
	assert.Nil(t, err)

}

func TestVerifier_VerifyJWZ(t *testing.T) {

	token := ` eyJhbGciOiJncm90aDE2IiwiY2lyY3VpdElkIjoiYXV0aCIsImNyaXQiOlsiY2lyY3VpdElkIl0sInR5cCI6IkpXWiJ9.eyJpZCI6ImE1NGI3YjJkLWJmMTUtNGU2NC1iZmQ1LTMxYzIwM2U3ZjIzYiIsInR5cCI6ImFwcGxpY2F0aW9uL2lkZW4zY29tbS1wbGFpbi1qc29uIiwidHlwZSI6Imh0dHBzOi8vaWRlbjMtY29tbXVuaWNhdGlvbi5pby9hdXRob3JpemF0aW9uLzEuMC9yZXNwb25zZSIsInRoaWQiOiJlZTkyYWIxMi0yNjcxLTQ1N2UtYWE1ZS04MTU4YzIwNWE5ODUiLCJib2R5Ijp7Im1lc3NhZ2UiOiJtZXNzYWdlIHRvIHNpZ24iLCJzY29wZSI6W3siaWQiOjEsImNpcmN1aXRfaWQiOiJjcmVkZW50aWFsQXRvbWljUXVlcnlNVFAiLCJwcm9vZiI6eyJwaV9hIjpbIjEzMzkxNzkyODU1ODc2MDY0MTU5OTYxOTcyNjM1NTkzMjkzNDIwMTA3Mzg0NTI4NTY4MDUxNTUzNDY0NDMxOTMwNzUxOTQ5MTY0MjIzIiwiMTM0MDIzNDE1NjUxNDQyNDM3MTQxMjYwODI5Mjg1NDYyODExOTY0NjQ5NTQ0NjAzNDkwMzE1NzI5MDg0Nzc5MDMzODgyODM2NTk2NyIsIjEiXSwicGlfYiI6W1siMTU2OTE4MTk5Nzk0NzUyMzIwOTQ1NTkxNzMwNzcyMjI2MTUzNDkxMDc2NzMyNTk3Mjk4ODA4NzI3NTQ1NDY0MjQ0MzU4MDQyMTA3ODAiLCI1MDk2MTM2Njk3NDg0Nzg5ODg4NDE0NjQ4MTgwMzg1NDIzNTkxMzc3ODkzMTk5Mzg3NzE4NTY3Mzk0ODU0MjAxMTE4MzA2ODE2MjY2Il0sWyIxNDQxNTQ2OTU1MTI1MTYwMDA5NzEzNDczNDg0MTIxMzg5NDEzMDQzOTU2MDY4MjAzNjczOTc5ODU0ODAyOTA3NjkxNTE4OTU3MTE5NiIsIjIwMDkwMDAwMjIzNDE0MTY2MDU3MzQxMDg1NjMyNDgzMTE4MTc1MzI0ODY4MTk3NTIyMzM0MjExOTkyMTI5NTI0OTEyNjczMDE0OTYyIl0sWyIxIiwiMCJdXSwicGlfYyI6WyIxMTQxNTUwMzEzMjI5NzMxMDIyNjA3MDkwOTc3OTAyNjA2MjQ2OTU5Mjk0NjkzNzY5OTY2MTE3MDE1MDk4ODc2NDI5NjcwNTg2MDY1MCIsIjEwNDU1NDIwNDQ1NjI4NTY1NDcwMTU0NjA5MjQ1OTk5NTEyNjY5MDIzMzk4MTI4NzkzNTM4NDc2ODY3NTYxNTIxMzIxMzU4NDA1Njc3IiwiMSJdLCJwcm90b2NvbCI6Imdyb3RoMTYifSwicHViX3NpZ25hbHMiOlsiMzc5OTQ5MTUwMTMwMjE0NzIzNDIwNTg5NjEwOTExMTYxODk1NDk1NjQ3Nzg5MDA2NjQ5Nzg1MjY0NzM4MTQxMjk5MTM1NDE0MjcyIiwiMTg2NTYxNDc1NDY2NjY5NDQ0ODQ0NTM4OTkyNDE5MTY0Njk1NDQwOTAyNTg4MTAxOTI4MDM5NDk1MjI3OTQ0OTA0OTMyNzEwMDUzMTMiLCIxIiwiMTczMzkyNzA2MjQzMDcwMDY1MjI4Mjk1ODc1NzA0MDIxMjg4MjUxNDc4NDU3NDQ2MDE3ODA2ODkyNTgwMzM2MjMwNTY0MDU5MzM3MDYiLCIyNjU5OTcwNzAwMjQ2MDE0NDM3OTA5Mjc1NTM3MDM4NDYzNTQ5NjU2MzgwNzQ1Mjg3ODk4OTE5MjM1MjYyNzI3MTc2ODM0MjUyOCIsIjE3MzM5MjcwNjI0MzA3MDA2NTIyODI5NTg3NTcwNDAyMTI4ODI1MTQ3ODQ1NzQ0NjAxNzgwNjg5MjU4MDMzNjIzMDU2NDA1OTMzNzA2IiwiMTY0MjA3NDM2MiIsIjEwNjU5MDg4MDA3MzMwMzQxODgxODQ5MDcxMDYzOTU1NjcwNDQ2MiIsIjIiLCI1IiwiODQwIiwiMTIwIiwiMzQwIiwiNTA5IiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIl19XX0sImZyb20iOiIxMTl0cWNlV2RSZDJGNlduQXlWdUZRUkZqSzNXVVhxMkxvclNQeUc5TEoiLCJ0byI6IjExMjVHSnFndzZZRXNLRndqNjNHWTg3TU14UEw5a3dES3hQVWl3TUxOWiJ9.eyJwcm9vZiI6eyJwaV9hIjpbIjk0NDkxMDYwMTY0NDk2ODA1ODc1ODgyNjg4NDA1NzAyNjc0NjM4NzE5NTI2MDAzMDY5ODE1ODc5OTE1OTE0MDU4MDk3NzU1NjQ4NCIsIjE5MDM2ODk1MTYyNTU1OTM0NDA3NjE0OTYzNDE0MzQ3NjY0MDAyMDQwMjA3MTk1MjA4NDI4NTM3ODg3Njc3NTI3ODc4OTU5ODg5NTEiLCIxIl0sInBpX2IiOltbIjg5ODQ4NDMwODMwNTk5Nzk5OTAxNjIzOTIzNzc3MTQ4MzkzMzMyOTIxMTE1NDM2Mjg5NzIwNjY5NTYyMTA3MDgxMDg4MDE1Njk3NSIsIjYxMTI0NTUyMTQ3MDg1MTc1NzAxMTEwMTA5NDUwMjE1OTQzMjkxNDk2MzY1OTc3NDE0NDk3MDE3NTcwNzcxMDIyMTMxNjk0MTU1OTAiXSxbIjExNjU2MDAxMzA0NTE2OTAwNTM5MzY4NzM3OTA3MTg5MzEwNjk5MTkyNzAxNjA1OTA0MDkwNDkyNTgxNzk0NTUyMjI2MTExODc4OTcwIiwiMTk2MzgwODk5NjMzMDI1MjYyNzI3ODM0NTA3NDQ1NjA4MTM3NTQyODYyMzA4Mjc3ODcxNDkwNTU4NjA1NDk2OTE1MjEwMTI4MTQ4MDkiXSxbIjEiLCIwIl1dLCJwaV9jIjpbIjEzODgwNDM2MjkzOTA4MTQyODU2MzYwMTg3NTQxNDQ1ODA4Mzc3ODI4Njg4MzA0NzUzOTMwNTA2NjA2ODM3MDczNzg3OTYzMDQ2NzcwIiwiMjU2MTI0Nzc2OTEyNTU5OTgwOTg5NTg1MjQ4OTM4MjQ2MTM2OTAzMjc1ODQwOTc3OTEzNjU4MDM4MTQxNTc0MjI3OTkyNTI2Mjk4OCIsIjEiXSwicHJvdG9jb2wiOiJncm90aDE2In0sInB1Yl9zaWduYWxzIjpbIjgzMzM5MDgzNTc1NjE2MTIxOTc1OTM0MDE1NDY5NzMyODg0Mjk5ODE0NDY3MDIyMzMwNjU1MTg3MTUzNzg5OTM1MDMzNjQzNDgyNzIiLCIxODY1NjE0NzU0NjY2Njk0NDQ4NDQ1Mzg5OTI0MTkxNjQ2OTU0NDA5MDI1ODgxMDE5MjgwMzk0OTUyMjc5NDQ5MDQ5MzI3MTAwNTMxMyIsIjM3OTk0OTE1MDEzMDIxNDcyMzQyMDU4OTYxMDkxMTE2MTg5NTQ5NTY0Nzc4OTAwNjY0OTc4NTI2NDczODE0MTI5OTEzNTQxNDI3MiJdfQ`

	authInstance := Verifier{verificationKeyloader, schemaLoader, stateResolver}
	parsedToken, err := authInstance.VerifyJWZ(context.Background(), token)
	assert.NoError(t, err)
	assert.Equal(t, parsedToken.Alg, "groth16")
}

func TestVerifier_FullVerify(t *testing.T) {

	// request
	verifierID := "1125GJqgw6YEsKFwj63GY87MMxPL9kwDKxPUiwMLNZ"
	callbackURL := "https://test.com/callback"
	reason := "age verification"

	var mtpProofRequest protocol.ZeroKnowledgeProofRequest
	mtpProofRequest.ID = 1
	mtpProofRequest.CircuitID = string(circuits.AtomicQueryMTPCircuitID)
	opt := true
	mtpProofRequest.Optional = &opt
	mtpProofRequest.Rules = map[string]interface{}{
		"query": pubsignals.Query{
			AllowedIssuers: []string{"*"},
			Req: map[string]interface{}{
				"countryCode": map[string]interface{}{
					"$nin": []int{
						840,
						120,
						340,
						509,
					},
				},
			},
			Schema: protocol.Schema{
				URL:  "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v2.json-ld",
				Type: "KYCCountryOfResidenceCredential",
			},
		},
	}
	request := CreateAuthorizationRequestWithMessage(reason, "message to sign", verifierID, callbackURL)
	request.Body.Scope = append(request.Body.Scope, mtpProofRequest)
	request.ID = "28494007-9c49-4f1a-9694-7700c08865bf"
	request.ThreadID = "ee92ab12-2671-457e-aa5e-8158c205a985" // because it's used in the response

	token := ` eyJhbGciOiJncm90aDE2IiwiY2lyY3VpdElkIjoiYXV0aCIsImNyaXQiOlsiY2lyY3VpdElkIl0sInR5cCI6IkpXWiJ9.eyJpZCI6ImE1NGI3YjJkLWJmMTUtNGU2NC1iZmQ1LTMxYzIwM2U3ZjIzYiIsInR5cCI6ImFwcGxpY2F0aW9uL2lkZW4zY29tbS1wbGFpbi1qc29uIiwidHlwZSI6Imh0dHBzOi8vaWRlbjMtY29tbXVuaWNhdGlvbi5pby9hdXRob3JpemF0aW9uLzEuMC9yZXNwb25zZSIsInRoaWQiOiJlZTkyYWIxMi0yNjcxLTQ1N2UtYWE1ZS04MTU4YzIwNWE5ODUiLCJib2R5Ijp7Im1lc3NhZ2UiOiJtZXNzYWdlIHRvIHNpZ24iLCJzY29wZSI6W3siaWQiOjEsImNpcmN1aXRfaWQiOiJjcmVkZW50aWFsQXRvbWljUXVlcnlNVFAiLCJwcm9vZiI6eyJwaV9hIjpbIjEzMzkxNzkyODU1ODc2MDY0MTU5OTYxOTcyNjM1NTkzMjkzNDIwMTA3Mzg0NTI4NTY4MDUxNTUzNDY0NDMxOTMwNzUxOTQ5MTY0MjIzIiwiMTM0MDIzNDE1NjUxNDQyNDM3MTQxMjYwODI5Mjg1NDYyODExOTY0NjQ5NTQ0NjAzNDkwMzE1NzI5MDg0Nzc5MDMzODgyODM2NTk2NyIsIjEiXSwicGlfYiI6W1siMTU2OTE4MTk5Nzk0NzUyMzIwOTQ1NTkxNzMwNzcyMjI2MTUzNDkxMDc2NzMyNTk3Mjk4ODA4NzI3NTQ1NDY0MjQ0MzU4MDQyMTA3ODAiLCI1MDk2MTM2Njk3NDg0Nzg5ODg4NDE0NjQ4MTgwMzg1NDIzNTkxMzc3ODkzMTk5Mzg3NzE4NTY3Mzk0ODU0MjAxMTE4MzA2ODE2MjY2Il0sWyIxNDQxNTQ2OTU1MTI1MTYwMDA5NzEzNDczNDg0MTIxMzg5NDEzMDQzOTU2MDY4MjAzNjczOTc5ODU0ODAyOTA3NjkxNTE4OTU3MTE5NiIsIjIwMDkwMDAwMjIzNDE0MTY2MDU3MzQxMDg1NjMyNDgzMTE4MTc1MzI0ODY4MTk3NTIyMzM0MjExOTkyMTI5NTI0OTEyNjczMDE0OTYyIl0sWyIxIiwiMCJdXSwicGlfYyI6WyIxMTQxNTUwMzEzMjI5NzMxMDIyNjA3MDkwOTc3OTAyNjA2MjQ2OTU5Mjk0NjkzNzY5OTY2MTE3MDE1MDk4ODc2NDI5NjcwNTg2MDY1MCIsIjEwNDU1NDIwNDQ1NjI4NTY1NDcwMTU0NjA5MjQ1OTk5NTEyNjY5MDIzMzk4MTI4NzkzNTM4NDc2ODY3NTYxNTIxMzIxMzU4NDA1Njc3IiwiMSJdLCJwcm90b2NvbCI6Imdyb3RoMTYifSwicHViX3NpZ25hbHMiOlsiMzc5OTQ5MTUwMTMwMjE0NzIzNDIwNTg5NjEwOTExMTYxODk1NDk1NjQ3Nzg5MDA2NjQ5Nzg1MjY0NzM4MTQxMjk5MTM1NDE0MjcyIiwiMTg2NTYxNDc1NDY2NjY5NDQ0ODQ0NTM4OTkyNDE5MTY0Njk1NDQwOTAyNTg4MTAxOTI4MDM5NDk1MjI3OTQ0OTA0OTMyNzEwMDUzMTMiLCIxIiwiMTczMzkyNzA2MjQzMDcwMDY1MjI4Mjk1ODc1NzA0MDIxMjg4MjUxNDc4NDU3NDQ2MDE3ODA2ODkyNTgwMzM2MjMwNTY0MDU5MzM3MDYiLCIyNjU5OTcwNzAwMjQ2MDE0NDM3OTA5Mjc1NTM3MDM4NDYzNTQ5NjU2MzgwNzQ1Mjg3ODk4OTE5MjM1MjYyNzI3MTc2ODM0MjUyOCIsIjE3MzM5MjcwNjI0MzA3MDA2NTIyODI5NTg3NTcwNDAyMTI4ODI1MTQ3ODQ1NzQ0NjAxNzgwNjg5MjU4MDMzNjIzMDU2NDA1OTMzNzA2IiwiMTY0MjA3NDM2MiIsIjEwNjU5MDg4MDA3MzMwMzQxODgxODQ5MDcxMDYzOTU1NjcwNDQ2MiIsIjIiLCI1IiwiODQwIiwiMTIwIiwiMzQwIiwiNTA5IiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIl19XX0sImZyb20iOiIxMTl0cWNlV2RSZDJGNlduQXlWdUZRUkZqSzNXVVhxMkxvclNQeUc5TEoiLCJ0byI6IjExMjVHSnFndzZZRXNLRndqNjNHWTg3TU14UEw5a3dES3hQVWl3TUxOWiJ9.eyJwcm9vZiI6eyJwaV9hIjpbIjk0NDkxMDYwMTY0NDk2ODA1ODc1ODgyNjg4NDA1NzAyNjc0NjM4NzE5NTI2MDAzMDY5ODE1ODc5OTE1OTE0MDU4MDk3NzU1NjQ4NCIsIjE5MDM2ODk1MTYyNTU1OTM0NDA3NjE0OTYzNDE0MzQ3NjY0MDAyMDQwMjA3MTk1MjA4NDI4NTM3ODg3Njc3NTI3ODc4OTU5ODg5NTEiLCIxIl0sInBpX2IiOltbIjg5ODQ4NDMwODMwNTk5Nzk5OTAxNjIzOTIzNzc3MTQ4MzkzMzMyOTIxMTE1NDM2Mjg5NzIwNjY5NTYyMTA3MDgxMDg4MDE1Njk3NSIsIjYxMTI0NTUyMTQ3MDg1MTc1NzAxMTEwMTA5NDUwMjE1OTQzMjkxNDk2MzY1OTc3NDE0NDk3MDE3NTcwNzcxMDIyMTMxNjk0MTU1OTAiXSxbIjExNjU2MDAxMzA0NTE2OTAwNTM5MzY4NzM3OTA3MTg5MzEwNjk5MTkyNzAxNjA1OTA0MDkwNDkyNTgxNzk0NTUyMjI2MTExODc4OTcwIiwiMTk2MzgwODk5NjMzMDI1MjYyNzI3ODM0NTA3NDQ1NjA4MTM3NTQyODYyMzA4Mjc3ODcxNDkwNTU4NjA1NDk2OTE1MjEwMTI4MTQ4MDkiXSxbIjEiLCIwIl1dLCJwaV9jIjpbIjEzODgwNDM2MjkzOTA4MTQyODU2MzYwMTg3NTQxNDQ1ODA4Mzc3ODI4Njg4MzA0NzUzOTMwNTA2NjA2ODM3MDczNzg3OTYzMDQ2NzcwIiwiMjU2MTI0Nzc2OTEyNTU5OTgwOTg5NTg1MjQ4OTM4MjQ2MTM2OTAzMjc1ODQwOTc3OTEzNjU4MDM4MTQxNTc0MjI3OTkyNTI2Mjk4OCIsIjEiXSwicHJvdG9jb2wiOiJncm90aDE2In0sInB1Yl9zaWduYWxzIjpbIjgzMzM5MDgzNTc1NjE2MTIxOTc1OTM0MDE1NDY5NzMyODg0Mjk5ODE0NDY3MDIyMzMwNjU1MTg3MTUzNzg5OTM1MDMzNjQzNDgyNzIiLCIxODY1NjE0NzU0NjY2Njk0NDQ4NDQ1Mzg5OTI0MTkxNjQ2OTU0NDA5MDI1ODgxMDE5MjgwMzk0OTUyMjc5NDQ5MDQ5MzI3MTAwNTMxMyIsIjM3OTk0OTE1MDEzMDIxNDcyMzQyMDU4OTYxMDkxMTE2MTg5NTQ5NTY0Nzc4OTAwNjY0OTc4NTI2NDczODE0MTI5OTEzNTQxNDI3MiJdfQ`

	authInstance := Verifier{verificationKeyloader, schemaLoader, stateResolver}
	_, err := authInstance.FullVerify(context.Background(), token, request)
	assert.Nil(t, err)
}

func TestVerifyAuthResponseWithEmptyReq(t *testing.T) {

	verifierID := "1125GJqgw6YEsKFwj63GY87MMxPL9kwDKxPUiwMLNZ"
	callbackURL := "https://test.com/callback"
	reason := "test"

	userID := "119tqceWdRd2F6WnAyVuFQRFjK3WUXq2LorSPyG9LJ"
	var zkReq protocol.ZeroKnowledgeProofRequest
	zkReq.ID = 1
	zkReq.CircuitID = string(circuits.AtomicQueryMTPCircuitID)
	opt := true
	zkReq.Optional = &opt
	zkReq.Rules = map[string]interface{}{
		"query": pubsignals.Query{
			AllowedIssuers: []string{"*"},
			Schema: protocol.Schema{
				URL:  "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v2.json-ld",
				Type: "KYCCountryOfResidenceCredential",
			},
		},
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
					ID:        1,
					CircuitID: string(circuits.AtomicQueryMTPCircuitID),
					ZKProof: types.ZKProof{
						Proof: &types.ProofData{
							A: []string{
								"9742806134969392226546322490560630802447930806537100408086160321763928272376",
								"21455791203277003434494375277451189817937636213176444019767120099596514163982",
								"1",
							},
							B: [][]string{
								{
									"10380825203862480352812509276126714433521593951138343399902602814224203230644",
									"3258713202006941217475014546591342349864153477480289203741647764981122849969",
								},
								{
									"1822645146824926970539316997069683858010941097218414131904374790154170166572",
									"10353710770765315368364178270577963995559055291780726291909607243297495512681",
								},
								{
									"1",
									"0",
								}},
							C: []string{
								"9484567403290042082168690530225028055268796074940883562365588128103915644358",
								"6661326208907807355087503512595101570698136414120018064634575604679380099060",
								"1",
							},
							Protocol: "groth16",
						},
						PubSignals: []string{
							"379949150130214723420589610911161895495647789006649785264738141299135414272",
							"18656147546666944484453899241916469544090258810192803949522794490493271005313",
							"1",
							"17339270624307006522829587570402128825147845744601780689258033623056405933706",
							"26599707002460144379092755370384635496563807452878989192352627271768342528",
							"17339270624307006522829587570402128825147845744601780689258033623056405933706",
							"1642074362",
							"106590880073303418818490710639556704462",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
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

	authInstance := Verifier{verificationKeyloader, schemaLoader, stateResolver}
	err := authInstance.VerifyAuthResponse(context.Background(), resp, authReq)
	assert.NoError(t, err)
}
