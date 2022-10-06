package auth

import (
	"context"
	"math/big"
	"testing"

	"github.com/google/uuid"
	"github.com/iden3/go-iden3-auth/loaders"
	"github.com/iden3/go-iden3-auth/pubsignals"
	"github.com/iden3/go-iden3-auth/state"
	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-rapidsnark/types"
	"github.com/iden3/iden3comm/packers"
	"github.com/iden3/iden3comm/protocol"
	"github.com/stretchr/testify/assert"

	"github.com/iden3/go-circuits"
)

var verificationKeyloader = &loaders.FSKeyLoader{Dir: "./testdata"}
var schemaLoader = &mockMemorySchemaLoader{}

var sender = "did:iden3:polygon:mumbai:4RzqiKYtZjWu8xf1jnts3FTpPnwTzW1HyUsdDGcDER6"
var senderDID, _ = core.ParseDID(sender)

var verifier = "did:iden3:polygon:mumbai:4RzkkAj2G1ugUEdSo676p5ot7dgQqZ8riTfv4Ev1YX2"

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
	return &state.ResolvedState{Latest: true, Genesis: false, TransitionTimestamp: 0}, nil
}

func TestCreateAuthorizationRequest(t *testing.T) {

	callbackURL := "https://test.com/callback"
	reason := "basic authentication"

	request := CreateAuthorizationRequest(reason, sender, callbackURL)
	assert.Len(t, request.Body.Scope, 0)
	assert.Equal(t, callbackURL, request.Body.CallbackURL)
	assert.Equal(t, sender, request.From)

}

func TestCreateAuthorizationRequestWithZKP(t *testing.T) {

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
	request := CreateAuthorizationRequestWithMessage(reason, "message to sign", verifier, callbackURL)
	request.Body.Scope = append(request.Body.Scope, mtpProofRequest)

	responseUUID := uuid.New()

	// response
	var message protocol.AuthorizationResponseMessage
	message.Typ = packers.MediaTypePlainMessage
	message.Type = protocol.AuthorizationResponseMessageType
	message.From = sender
	message.To = verifier
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
							"16211956402207631381176468379728798423667930255981755004420230738449664690789",
							"9004778740389807084354971283763172719260701729052628681856488259422542142246",
							"1",
						},
						B: [][]string{
							{
								"1867213032783297476060755068211475075858961965863624879298845829586299184181",
								"5447031243269227173277400395615691016669381340191201590713671817196393706107",
							},
							{
								"17580517094023255178200218409218051221258751870069962961809730586923792493375",
								"12852098816013633547562042667268205467432181507727121675212229110928894118845",
							},
							{
								"1",
								"0",
							}},
						C: []string{
							"11024440282133310283168486346789455438597411678641019832906508201996664465537",
							"16945790247011207441581463668502066293637526289646384880071951785028068863319",
							"1",
						},
						Protocol: "groth16",
					},
					PubSignals: []string{
						"326950639933209984096878120644736617046275723209353386907645117784580620769",
						"18656147546666944484453899241916469544090258810192803949522794490493271005313",
						"1",
						"14473004656059607514898969789987687802517264655755422269466843781861921926818",
						"425907143642375002864917990538284220073575168146768873727835628763900412385",
						"14473004656059607514898969789987687802517264655755422269466843781861921926818",
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

	token := `eyJhbGciOiJncm90aDE2IiwiY2lyY3VpdElkIjoiYXV0aCIsImNyaXQiOlsiY2lyY3VpdElkIl0sInR5cCI6IkpXWiJ9.eyJpZCI6ImI5N2I4ODY2LTExNTAtNGM2OS05ZmQxLTc0NDA0MTkyZTMxYiIsInR5cCI6ImFwcGxpY2F0aW9uL2lkZW4zY29tbS1wbGFpbi1qc29uIiwidHlwZSI6Imh0dHBzOi8vaWRlbjMtY29tbXVuaWNhdGlvbi5pby9hdXRob3JpemF0aW9uLzEuMC9yZXNwb25zZSIsInRoaWQiOiJkYmUyZDEyNy01ZDM0LTQwYTItOWU0YS0zZTMyNzAxM2E0NzgiLCJib2R5Ijp7Im1lc3NhZ2UiOiJtZXNzYWdlIHRvIHNpZ24iLCJzY29wZSI6W3siaWQiOjEsImNpcmN1aXRfaWQiOiJjcmVkZW50aWFsQXRvbWljUXVlcnlNVFAiLCJwcm9vZiI6eyJwaV9hIjpbIjE2MjExOTU2NDAyMjA3NjMxMzgxMTc2NDY4Mzc5NzI4Nzk4NDIzNjY3OTMwMjU1OTgxNzU1MDA0NDIwMjMwNzM4NDQ5NjY0NjkwNzg5IiwiOTAwNDc3ODc0MDM4OTgwNzA4NDM1NDk3MTI4Mzc2MzE3MjcxOTI2MDcwMTcyOTA1MjYyODY4MTg1NjQ4ODI1OTQyMjU0MjE0MjI0NiIsIjEiXSwicGlfYiI6W1siMTg2NzIxMzAzMjc4MzI5NzQ3NjA2MDc1NTA2ODIxMTQ3NTA3NTg1ODk2MTk2NTg2MzYyNDg3OTI5ODg0NTgyOTU4NjI5OTE4NDE4MSIsIjU0NDcwMzEyNDMyNjkyMjcxNzMyNzc0MDAzOTU2MTU2OTEwMTY2NjkzODEzNDAxOTEyMDE1OTA3MTM2NzE4MTcxOTYzOTM3MDYxMDciXSxbIjE3NTgwNTE3MDk0MDIzMjU1MTc4MjAwMjE4NDA5MjE4MDUxMjIxMjU4NzUxODcwMDY5OTYyOTYxODA5NzMwNTg2OTIzNzkyNDkzMzc1IiwiMTI4NTIwOTg4MTYwMTM2MzM1NDc1NjIwNDI2NjcyNjgyMDU0Njc0MzIxODE1MDc3MjcxMjE2NzUyMTIyMjkxMTA5Mjg4OTQxMTg4NDUiXSxbIjEiLCIwIl1dLCJwaV9jIjpbIjExMDI0NDQwMjgyMTMzMzEwMjgzMTY4NDg2MzQ2Nzg5NDU1NDM4NTk3NDExNjc4NjQxMDE5ODMyOTA2NTA4MjAxOTk2NjY0NDY1NTM3IiwiMTY5NDU3OTAyNDcwMTEyMDc0NDE1ODE0NjM2Njg1MDIwNjYyOTM2Mzc1MjYyODk2NDYzODQ4ODAwNzE5NTE3ODUwMjgwNjg4NjMzMTkiLCIxIl0sInByb3RvY29sIjoiZ3JvdGgxNiJ9LCJwdWJfc2lnbmFscyI6WyIzMjY5NTA2Mzk5MzMyMDk5ODQwOTY4NzgxMjA2NDQ3MzY2MTcwNDYyNzU3MjMyMDkzNTMzODY5MDc2NDUxMTc3ODQ1ODA2MjA3NjkiLCIxODY1NjE0NzU0NjY2Njk0NDQ4NDQ1Mzg5OTI0MTkxNjQ2OTU0NDA5MDI1ODgxMDE5MjgwMzk0OTUyMjc5NDQ5MDQ5MzI3MTAwNTMxMyIsIjEiLCIxNDQ3MzAwNDY1NjA1OTYwNzUxNDg5ODk2OTc4OTk4NzY4NzgwMjUxNzI2NDY1NTc1NTQyMjI2OTQ2Njg0Mzc4MTg2MTkyMTkyNjgxOCIsIjQyNTkwNzE0MzY0MjM3NTAwMjg2NDkxNzk5MDUzODI4NDIyMDA3MzU3NTE2ODE0Njc2ODg3MzcyNzgzNTYyODc2MzkwMDQxMjM4NSIsIjE0NDczMDA0NjU2MDU5NjA3NTE0ODk4OTY5Nzg5OTg3Njg3ODAyNTE3MjY0NjU1NzU1NDIyMjY5NDY2ODQzNzgxODYxOTIxOTI2ODE4IiwiMTY0MjA3NDM2MiIsIjEwNjU5MDg4MDA3MzMwMzQxODgxODQ5MDcxMDYzOTU1NjcwNDQ2MiIsIjIiLCI1IiwiODQwIiwiMTIwIiwiMzQwIiwiNTA5IiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIl19XX0sImZyb20iOiJkaWQ6aWRlbjM6cG9seWdvbjptdW1iYWk6NFJ6cWlLWXRaald1OHhmMWpudHMzRlRwUG53VHpXMUh5VXNkREdjREVSNiIsInRvIjoiZGlkOmlkZW4zOnBvbHlnb246bXVtYmFpOjRSemtrQWoyRzF1Z1VFZFNvNjc2cDVvdDdkZ1FxWjhyaVRmdjRFdjFZWDIifQ.eyJwcm9vZiI6eyJwaV9hIjpbIjk0NzU4OTExMTI2MTIyOTI2NjA3ODk4MTQ3MDE0ODI4OTA0MTk1MjkzMDg5MDkyNjA5OTYxMjk3MTE1MzQxMDczNTI2Njc0MjY3MTYiLCIxNjI4MTk2MTc1OTkwMDQxMzQ3OTg4NzMzNjA2NzI3Njc2MTE4MTEwNTY0NTgyNTUwNjExNTg4MjMxNzgwMjMxNjg3NDg4NzQyMjQyMiIsIjEiXSwicGlfYiI6W1siMTY2NzU5NzEzNTUxMjcxMzQ4Njg2NDIzODU4MTg5NjAwOTIyMTUxNjc5MDU5MDExOTI4MTQ3NzcwNjc2MTU1OTgwMTI3OTQyNjIxNzYiLCI1ODU0ODg3NDQxOTY5Mjg4OTY3MjcwNzA5NzIwMzM1MzY4NDI0ODg2NzEzMDA2MjM5NDk3ODczNzkyMzM5ODU4MzM0NzEyNzE2NTUwIl0sWyIxOTE4Nzk2Mzg3NDAwMDg2NjQ5MTYzMTk3MDQ3MzQ4NTYyMzczNDMyODEyNTI0NDc4OTEwNTk1NTY5MDI3ODc5MzMwOTQ4NjMyNzExNyIsIjkxNjU0MzM3OTIxOTg4MzUyNjk2MTM0NzMzODYyMzg1ODY4NDM3NDIyMTMyMjgzMTk3NTUyMDI3OTIxNTI3MzI4ODg2ODAyMTQ4MSJdLFsiMSIsIjAiXV0sInBpX2MiOlsiOTU5NDg1OTY5MTAyODE1NzI5NzcwNzA1MTA1MDU3NzUzNjMyMjAzNzQ4NDg5MDkyNTMxNzIxNjYyMDk4MDA3NTAxMzg3OTU0MzM2NyIsIjU5MTEwMjM2MDkxNjE3NjMxMDcxNDY3NTY0NDk4Mjg2NjYwMzc5OTQ3MjgwMTgyODAzODQ5NzE2NzY0MzIxOTQyMjk5MjI0OTk3MjQiLCIxIl0sInByb3RvY29sIjoiZ3JvdGgxNiJ9LCJwdWJfc2lnbmFscyI6WyI4MTcwODA3MDQ0MTMzMTQ2ODE3MDgzOTU4ODk4ODA4NzI3NjU4NjUzODE4MzExNTM4NzI0ODQ2ODk0MDE0NDk5ODI4NDY3NjA5MjA5IiwiMTg2NTYxNDc1NDY2NjY5NDQ0ODQ0NTM4OTkyNDE5MTY0Njk1NDQwOTAyNTg4MTAxOTI4MDM5NDk1MjI3OTQ0OTA0OTMyNzEwMDUzMTMiLCIzMjY5NTA2Mzk5MzMyMDk5ODQwOTY4NzgxMjA2NDQ3MzY2MTcwNDYyNzU3MjMyMDkzNTMzODY5MDc2NDUxMTc3ODQ1ODA2MjA3NjkiXX0`

	authInstance := Verifier{verificationKeyloader, schemaLoader, stateResolver}
	parsedToken, err := authInstance.VerifyJWZ(context.Background(), token)
	assert.NoError(t, err)
	assert.Equal(t, parsedToken.Alg, "groth16")
}

func TestVerifier_FullVerify(t *testing.T) {

	// request
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
	request := CreateAuthorizationRequestWithMessage(reason, "message to sign", verifier, callbackURL)
	request.Body.Scope = append(request.Body.Scope, mtpProofRequest)
	request.ID = "cca7127f-6c3b-492f-ae18-6819e24c15ac"
	request.ThreadID = "70596e6c-238e-4f09-9bbb-fa4db9c1caba" // because it's used in the response

	token := `eyJhbGciOiJncm90aDE2IiwiY2lyY3VpdElkIjoiYXV0aCIsImNyaXQiOlsiY2lyY3VpdElkIl0sInR5cCI6IkpXWiJ9.eyJpZCI6ImI5N2I4ODY2LTExNTAtNGM2OS05ZmQxLTc0NDA0MTkyZTMxYiIsInR5cCI6ImFwcGxpY2F0aW9uL2lkZW4zY29tbS1wbGFpbi1qc29uIiwidHlwZSI6Imh0dHBzOi8vaWRlbjMtY29tbXVuaWNhdGlvbi5pby9hdXRob3JpemF0aW9uLzEuMC9yZXNwb25zZSIsInRoaWQiOiJkYmUyZDEyNy01ZDM0LTQwYTItOWU0YS0zZTMyNzAxM2E0NzgiLCJib2R5Ijp7Im1lc3NhZ2UiOiJtZXNzYWdlIHRvIHNpZ24iLCJzY29wZSI6W3siaWQiOjEsImNpcmN1aXRfaWQiOiJjcmVkZW50aWFsQXRvbWljUXVlcnlNVFAiLCJwcm9vZiI6eyJwaV9hIjpbIjE2MjExOTU2NDAyMjA3NjMxMzgxMTc2NDY4Mzc5NzI4Nzk4NDIzNjY3OTMwMjU1OTgxNzU1MDA0NDIwMjMwNzM4NDQ5NjY0NjkwNzg5IiwiOTAwNDc3ODc0MDM4OTgwNzA4NDM1NDk3MTI4Mzc2MzE3MjcxOTI2MDcwMTcyOTA1MjYyODY4MTg1NjQ4ODI1OTQyMjU0MjE0MjI0NiIsIjEiXSwicGlfYiI6W1siMTg2NzIxMzAzMjc4MzI5NzQ3NjA2MDc1NTA2ODIxMTQ3NTA3NTg1ODk2MTk2NTg2MzYyNDg3OTI5ODg0NTgyOTU4NjI5OTE4NDE4MSIsIjU0NDcwMzEyNDMyNjkyMjcxNzMyNzc0MDAzOTU2MTU2OTEwMTY2NjkzODEzNDAxOTEyMDE1OTA3MTM2NzE4MTcxOTYzOTM3MDYxMDciXSxbIjE3NTgwNTE3MDk0MDIzMjU1MTc4MjAwMjE4NDA5MjE4MDUxMjIxMjU4NzUxODcwMDY5OTYyOTYxODA5NzMwNTg2OTIzNzkyNDkzMzc1IiwiMTI4NTIwOTg4MTYwMTM2MzM1NDc1NjIwNDI2NjcyNjgyMDU0Njc0MzIxODE1MDc3MjcxMjE2NzUyMTIyMjkxMTA5Mjg4OTQxMTg4NDUiXSxbIjEiLCIwIl1dLCJwaV9jIjpbIjExMDI0NDQwMjgyMTMzMzEwMjgzMTY4NDg2MzQ2Nzg5NDU1NDM4NTk3NDExNjc4NjQxMDE5ODMyOTA2NTA4MjAxOTk2NjY0NDY1NTM3IiwiMTY5NDU3OTAyNDcwMTEyMDc0NDE1ODE0NjM2Njg1MDIwNjYyOTM2Mzc1MjYyODk2NDYzODQ4ODAwNzE5NTE3ODUwMjgwNjg4NjMzMTkiLCIxIl0sInByb3RvY29sIjoiZ3JvdGgxNiJ9LCJwdWJfc2lnbmFscyI6WyIzMjY5NTA2Mzk5MzMyMDk5ODQwOTY4NzgxMjA2NDQ3MzY2MTcwNDYyNzU3MjMyMDkzNTMzODY5MDc2NDUxMTc3ODQ1ODA2MjA3NjkiLCIxODY1NjE0NzU0NjY2Njk0NDQ4NDQ1Mzg5OTI0MTkxNjQ2OTU0NDA5MDI1ODgxMDE5MjgwMzk0OTUyMjc5NDQ5MDQ5MzI3MTAwNTMxMyIsIjEiLCIxNDQ3MzAwNDY1NjA1OTYwNzUxNDg5ODk2OTc4OTk4NzY4NzgwMjUxNzI2NDY1NTc1NTQyMjI2OTQ2Njg0Mzc4MTg2MTkyMTkyNjgxOCIsIjQyNTkwNzE0MzY0MjM3NTAwMjg2NDkxNzk5MDUzODI4NDIyMDA3MzU3NTE2ODE0Njc2ODg3MzcyNzgzNTYyODc2MzkwMDQxMjM4NSIsIjE0NDczMDA0NjU2MDU5NjA3NTE0ODk4OTY5Nzg5OTg3Njg3ODAyNTE3MjY0NjU1NzU1NDIyMjY5NDY2ODQzNzgxODYxOTIxOTI2ODE4IiwiMTY0MjA3NDM2MiIsIjEwNjU5MDg4MDA3MzMwMzQxODgxODQ5MDcxMDYzOTU1NjcwNDQ2MiIsIjIiLCI1IiwiODQwIiwiMTIwIiwiMzQwIiwiNTA5IiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIl19XX0sImZyb20iOiJkaWQ6aWRlbjM6cG9seWdvbjptdW1iYWk6NFJ6cWlLWXRaald1OHhmMWpudHMzRlRwUG53VHpXMUh5VXNkREdjREVSNiIsInRvIjoiZGlkOmlkZW4zOnBvbHlnb246bXVtYmFpOjRSemtrQWoyRzF1Z1VFZFNvNjc2cDVvdDdkZ1FxWjhyaVRmdjRFdjFZWDIifQ.eyJwcm9vZiI6eyJwaV9hIjpbIjk0NzU4OTExMTI2MTIyOTI2NjA3ODk4MTQ3MDE0ODI4OTA0MTk1MjkzMDg5MDkyNjA5OTYxMjk3MTE1MzQxMDczNTI2Njc0MjY3MTYiLCIxNjI4MTk2MTc1OTkwMDQxMzQ3OTg4NzMzNjA2NzI3Njc2MTE4MTEwNTY0NTgyNTUwNjExNTg4MjMxNzgwMjMxNjg3NDg4NzQyMjQyMiIsIjEiXSwicGlfYiI6W1siMTY2NzU5NzEzNTUxMjcxMzQ4Njg2NDIzODU4MTg5NjAwOTIyMTUxNjc5MDU5MDExOTI4MTQ3NzcwNjc2MTU1OTgwMTI3OTQyNjIxNzYiLCI1ODU0ODg3NDQxOTY5Mjg4OTY3MjcwNzA5NzIwMzM1MzY4NDI0ODg2NzEzMDA2MjM5NDk3ODczNzkyMzM5ODU4MzM0NzEyNzE2NTUwIl0sWyIxOTE4Nzk2Mzg3NDAwMDg2NjQ5MTYzMTk3MDQ3MzQ4NTYyMzczNDMyODEyNTI0NDc4OTEwNTk1NTY5MDI3ODc5MzMwOTQ4NjMyNzExNyIsIjkxNjU0MzM3OTIxOTg4MzUyNjk2MTM0NzMzODYyMzg1ODY4NDM3NDIyMTMyMjgzMTk3NTUyMDI3OTIxNTI3MzI4ODg2ODAyMTQ4MSJdLFsiMSIsIjAiXV0sInBpX2MiOlsiOTU5NDg1OTY5MTAyODE1NzI5NzcwNzA1MTA1MDU3NzUzNjMyMjAzNzQ4NDg5MDkyNTMxNzIxNjYyMDk4MDA3NTAxMzg3OTU0MzM2NyIsIjU5MTEwMjM2MDkxNjE3NjMxMDcxNDY3NTY0NDk4Mjg2NjYwMzc5OTQ3MjgwMTgyODAzODQ5NzE2NzY0MzIxOTQyMjk5MjI0OTk3MjQiLCIxIl0sInByb3RvY29sIjoiZ3JvdGgxNiJ9LCJwdWJfc2lnbmFscyI6WyI4MTcwODA3MDQ0MTMzMTQ2ODE3MDgzOTU4ODk4ODA4NzI3NjU4NjUzODE4MzExNTM4NzI0ODQ2ODk0MDE0NDk5ODI4NDY3NjA5MjA5IiwiMTg2NTYxNDc1NDY2NjY5NDQ0ODQ0NTM4OTkyNDE5MTY0Njk1NDQwOTAyNTg4MTAxOTI4MDM5NDk1MjI3OTQ0OTA0OTMyNzEwMDUzMTMiLCIzMjY5NTA2Mzk5MzMyMDk5ODQwOTY4NzgxMjA2NDQ3MzY2MTcwNDYyNzU3MjMyMDkzNTMzODY5MDc2NDUxMTc3ODQ1ODA2MjA3NjkiXX0`

	authInstance := Verifier{verificationKeyloader, schemaLoader, stateResolver}
	_, err := authInstance.FullVerify(context.Background(), token, request)
	assert.Nil(t, err)

}

func TestVerifyAuthResponseWithEmptyReq(t *testing.T) {

	callbackURL := "https://test.com/callback"
	reason := "test"

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

	authReq := CreateAuthorizationRequestWithMessage(reason, "test", verifier, callbackURL)
	authReq.Body.Scope = append(authReq.Body.Scope, zkReq)
	authReq.ID = "cca7127f-6c3b-492f-ae18-6819e24c15ac"
	authReq.ThreadID = "70596e6c-238e-4f09-9bbb-fa4db9c1caba"

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
								"153392573288373153761846808176918966740697630417625340355534332972135429115",
								"9523131110764050551345751058916565344212608506457934267607153890412024986455",
								"1",
							},
							B: [][]string{
								{
									"165730040537455653453205443548354455293085922225576044081446282570423946841",
									"7731081747921388983220309005398922645721258950377832763937539772654569402300",
								},
								{
									"12216175931440522889777982411976329598479519759470030053113202614504903391147",
									"4523059248327270973687940512382147176412254135216210709540316921051425406972",
								},
								{
									"1",
									"0",
								}},
							C: []string{
								"19144928063812564410706109431937408098131613580348599926923812030595447521955",
								"2532045365899045706141580257192121486372974275247425788963472575631794239746",
								"1",
							},
							Protocol: "groth16",
						},
						PubSignals: []string{
							"326950639933209984096878120644736617046275723209353386907645117784580620769",
							"18656147546666944484453899241916469544090258810192803949522794490493271005313",
							"1",
							"14473004656059607514898969789987687802517264655755422269466843781861921926818",
							"425907143642375002864917990538284220073575168146768873727835628763900412385",
							"14473004656059607514898969789987687802517264655755422269466843781861921926818",
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
		From: sender,
		To:   authReq.From,
	}

	authInstance := Verifier{verificationKeyloader, schemaLoader, stateResolver}
	err := authInstance.VerifyAuthResponse(context.Background(), resp, authReq)
	assert.NoError(t, err)
}
