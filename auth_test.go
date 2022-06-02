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
							"957698408427964949373649712039920043210974666537246242527666231574736447215",
							"4086301798091555580700861865212439093760939259461303470105592576075967110809",
							"1",
						},
						B: [][]string{
							{
								"17761559932897315893618895130972320113328240504534127684296053239008480650132",
								"5632193781365169642645888319571038406614807943044397798965094551600628234503",
							},
							{
								"1365440307473149802051965484085369690014133594254254856398071522896525497247",
								"9143247083381732337710902360194843027755305930598838459668134140717530368519",
							},
							{
								"1",
								"0",
							}},
						C: []string{
							"16707768020019049851803695616000699953210287095055797633254316035548791886996",
							"20859199949100338932805050654787060104015161388984781255169527105633884420687",
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

	token := `eyJhbGciOiJncm90aDE2IiwiY2lyY3VpdElkIjoiYXV0aCIsImNyaXQiOlsiY2lyY3VpdElkIl0sInR5cCI6IkpXWiJ9.eyJpZCI6IjA5YjM4NDE1LTY3ZjAtNGE2Ny1hZTRhLTA3M2U4MGQzODg3MiIsInRoaWQiOiI3ZjM4YTE5My0wOTE4LTRhNDgtOWZhYy0zNmFkZmRiOGI1NDIiLCJ0eXAiOiJhcHBsaWNhdGlvbi9pZGVuM2NvbW0tcGxhaW4tanNvbiIsInR5cGUiOiJodHRwczovL2lkZW4zLWNvbW11bmljYXRpb24uaW8vYXV0aG9yaXphdGlvbi8xLjAvcmVzcG9uc2UiLCJmcm9tIjoiMTE5dHFjZVdkUmQyRjZXbkF5VnVGUVJGakszV1VYcTJMb3JTUHlHOUxKIiwidG8iOiIxMTI1R0pxZ3c2WUVzS0Z3ajYzR1k4N01NeFBMOWt3REt4UFVpd01MTloiLCJib2R5Ijp7Im1lc3NhZ2UiOiJtZXNzYWdlIHRvIHNpZ24iLCJzY29wZSI6W3siaWQiOjEsImNpcmN1aXRfaWQiOiJjcmVkZW50aWFsQXRvbWljUXVlcnlNVFAiLCJwcm9vZiI6eyJwaV9hIjpbIjk1NzY5ODQwODQyNzk2NDk0OTM3MzY0OTcxMjAzOTkyMDA0MzIxMDk3NDY2NjUzNzI0NjI0MjUyNzY2NjIzMTU3NDczNjQ0NzIxNSIsIjQwODYzMDE3OTgwOTE1NTU1ODA3MDA4NjE4NjUyMTI0MzkwOTM3NjA5MzkyNTk0NjEzMDM0NzAxMDU1OTI1NzYwNzU5NjcxMTA4MDkiLCIxIl0sInBpX2IiOltbIjE3NzYxNTU5OTMyODk3MzE1ODkzNjE4ODk1MTMwOTcyMzIwMTEzMzI4MjQwNTA0NTM0MTI3Njg0Mjk2MDUzMjM5MDA4NDgwNjUwMTMyIiwiNTYzMjE5Mzc4MTM2NTE2OTY0MjY0NTg4ODMxOTU3MTAzODQwNjYxNDgwNzk0MzA0NDM5Nzc5ODk2NTA5NDU1MTYwMDYyODIzNDUwMyJdLFsiMTM2NTQ0MDMwNzQ3MzE0OTgwMjA1MTk2NTQ4NDA4NTM2OTY5MDAxNDEzMzU5NDI1NDI1NDg1NjM5ODA3MTUyMjg5NjUyNTQ5NzI0NyIsIjkxNDMyNDcwODMzODE3MzIzMzc3MTA5MDIzNjAxOTQ4NDMwMjc3NTUzMDU5MzA1OTg4Mzg0NTk2NjgxMzQxNDA3MTc1MzAzNjg1MTkiXSxbIjEiLCIwIl1dLCJwaV9jIjpbIjE2NzA3NzY4MDIwMDE5MDQ5ODUxODAzNjk1NjE2MDAwNjk5OTUzMjEwMjg3MDk1MDU1Nzk3NjMzMjU0MzE2MDM1NTQ4NzkxODg2OTk2IiwiMjA4NTkxOTk5NDkxMDAzMzg5MzI4MDUwNTA2NTQ3ODcwNjAxMDQwMTUxNjEzODg5ODQ3ODEyNTUxNjk1MjcxMDU2MzM4ODQ0MjA2ODciLCIxIl0sInByb3RvY29sIjoiZ3JvdGgxNiIsImN1cnZlIjoiYm4xMjgifSwicHViX3NpZ25hbHMiOlsiMzc5OTQ5MTUwMTMwMjE0NzIzNDIwNTg5NjEwOTExMTYxODk1NDk1NjQ3Nzg5MDA2NjQ5Nzg1MjY0NzM4MTQxMjk5MTM1NDE0MjcyIiwiMTg2NTYxNDc1NDY2NjY5NDQ0ODQ0NTM4OTkyNDE5MTY0Njk1NDQwOTAyNTg4MTAxOTI4MDM5NDk1MjI3OTQ0OTA0OTMyNzEwMDUzMTMiLCIxIiwiMTczMzkyNzA2MjQzMDcwMDY1MjI4Mjk1ODc1NzA0MDIxMjg4MjUxNDc4NDU3NDQ2MDE3ODA2ODkyNTgwMzM2MjMwNTY0MDU5MzM3MDYiLCIyNjU5OTcwNzAwMjQ2MDE0NDM3OTA5Mjc1NTM3MDM4NDYzNTQ5NjU2MzgwNzQ1Mjg3ODk4OTE5MjM1MjYyNzI3MTc2ODM0MjUyOCIsIjE2NDIwNzQzNjIiLCIxMDY1OTA4ODAwNzMzMDM0MTg4MTg0OTA3MTA2Mzk1NTY3MDQ0NjIiLCIyIiwiNSIsIjg0MCIsIjEyMCIsIjM0MCIsIjUwOSIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCJdfV19fQ.eyJwcm9vZiI6eyJwaV9hIjpbIjMwMTc3ODIzODI1MzEwODkxMzY0NzgzNjU4MjAzMDMwNDY1NDkyMDYwMjA5MzEyNjc0NjgwNzk4NzY2ODM5NDE5MjcxMDgyNDkxNDEiLCI0OTAyMzUzODc4OTI0MTk2NzUyMTI2NDY2MTczMTM3NjQ0MjE4MDY2MTY0MDE5ODc4NDM4MzU3MDc0NDkwNjU4MTY2MjUyNTMxMzIxIiwiMSJdLCJwaV9iIjpbWyIxMjExNDEwOTAwNzkxMDg1NjM1MTk4ODgxNzQ0MjY1NTE3NjY3NTQ0OTE5NDcyOTc4MzYyNjQxNjUyMjY5NjAwMTA1NjIyMjA1MDA3NCIsIjE3NzIyMDA5NDMxNjI0MzUwMDAzMTU4MjgwOTcxNzk1NDQ2NTgwMzkxNTIzOTY3NzYxMzI4MzIzNjU4NDgxMTc2NDM3MTYxNzkxOTU2Il0sWyIxNzYyMzU3NzEzMzgzNzU4MDEzNzY4MDQ3NDQwNzk2NjY5OTA5Nzc0MDQxMzk1ODkxNzU2Njc0ODE4OTQ3OTM0NDQ2OTY5MTY1MDUyOCIsIjIxNDg2ODU3NDI2OTU4NTgxNzE4MjYwNDU4NzgyMjUxMjUwNzcwNTg0NzU0NzkyMDc4MTIwNDA0NzM3NDkzNzI3Njg1NTg3MjExNjM0Il0sWyIxIiwiMCJdXSwicGlfYyI6WyIxNjY4OTYyNDQ2ODc3MTI5MTc0MDY1MzY2MjczMjYxNzQzODEyODAwMzc2NzQyNDUwMDI0NjIyODI3NjA3MTYzMDI5NjQ4MjUxNTM0NiIsIjE1NDI3MzQxMDYxNzcxNDYyNjI1OTg3NjkzNzI4NjY0Njk0MTA0Mzk0OTcxNjE5NzUyOTk2NjUyNTQ2OTkzNzEwNjM5MDQ3NzMzNjE4IiwiMSJdLCJwcm90b2NvbCI6Imdyb3RoMTYifSwicHViX3NpZ25hbHMiOlsiODQ5NTg4MzgyMTE1NzY5NjE2MjY1NDAzNDE4MDIwNjk2OTU1NjYxNTQ5NzgxOTM2Mzc4OTc4NTUyMTI4MzQ5OTk3MDQ4MTk4MDk0MCIsIjE4NjU2MTQ3NTQ2NjY2OTQ0NDg0NDUzODk5MjQxOTE2NDY5NTQ0MDkwMjU4ODEwMTkyODAzOTQ5NTIyNzk0NDkwNDkzMjcxMDA1MzEzIiwiMzc5OTQ5MTUwMTMwMjE0NzIzNDIwNTg5NjEwOTExMTYxODk1NDk1NjQ3Nzg5MDA2NjQ5Nzg1MjY0NzM4MTQxMjk5MTM1NDE0MjcyIl19`

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
	request.ThreadID = "7f38a193-0918-4a48-9fac-36adfdb8b542" // because it's used in the response

	token := `eyJhbGciOiJncm90aDE2IiwiY2lyY3VpdElkIjoiYXV0aCIsImNyaXQiOlsiY2lyY3VpdElkIl0sInR5cCI6IkpXWiJ9.eyJpZCI6IjA5YjM4NDE1LTY3ZjAtNGE2Ny1hZTRhLTA3M2U4MGQzODg3MiIsInRoaWQiOiI3ZjM4YTE5My0wOTE4LTRhNDgtOWZhYy0zNmFkZmRiOGI1NDIiLCJ0eXAiOiJhcHBsaWNhdGlvbi9pZGVuM2NvbW0tcGxhaW4tanNvbiIsInR5cGUiOiJodHRwczovL2lkZW4zLWNvbW11bmljYXRpb24uaW8vYXV0aG9yaXphdGlvbi8xLjAvcmVzcG9uc2UiLCJmcm9tIjoiMTE5dHFjZVdkUmQyRjZXbkF5VnVGUVJGakszV1VYcTJMb3JTUHlHOUxKIiwidG8iOiIxMTI1R0pxZ3c2WUVzS0Z3ajYzR1k4N01NeFBMOWt3REt4UFVpd01MTloiLCJib2R5Ijp7Im1lc3NhZ2UiOiJtZXNzYWdlIHRvIHNpZ24iLCJzY29wZSI6W3siaWQiOjEsImNpcmN1aXRfaWQiOiJjcmVkZW50aWFsQXRvbWljUXVlcnlNVFAiLCJwcm9vZiI6eyJwaV9hIjpbIjk1NzY5ODQwODQyNzk2NDk0OTM3MzY0OTcxMjAzOTkyMDA0MzIxMDk3NDY2NjUzNzI0NjI0MjUyNzY2NjIzMTU3NDczNjQ0NzIxNSIsIjQwODYzMDE3OTgwOTE1NTU1ODA3MDA4NjE4NjUyMTI0MzkwOTM3NjA5MzkyNTk0NjEzMDM0NzAxMDU1OTI1NzYwNzU5NjcxMTA4MDkiLCIxIl0sInBpX2IiOltbIjE3NzYxNTU5OTMyODk3MzE1ODkzNjE4ODk1MTMwOTcyMzIwMTEzMzI4MjQwNTA0NTM0MTI3Njg0Mjk2MDUzMjM5MDA4NDgwNjUwMTMyIiwiNTYzMjE5Mzc4MTM2NTE2OTY0MjY0NTg4ODMxOTU3MTAzODQwNjYxNDgwNzk0MzA0NDM5Nzc5ODk2NTA5NDU1MTYwMDYyODIzNDUwMyJdLFsiMTM2NTQ0MDMwNzQ3MzE0OTgwMjA1MTk2NTQ4NDA4NTM2OTY5MDAxNDEzMzU5NDI1NDI1NDg1NjM5ODA3MTUyMjg5NjUyNTQ5NzI0NyIsIjkxNDMyNDcwODMzODE3MzIzMzc3MTA5MDIzNjAxOTQ4NDMwMjc3NTUzMDU5MzA1OTg4Mzg0NTk2NjgxMzQxNDA3MTc1MzAzNjg1MTkiXSxbIjEiLCIwIl1dLCJwaV9jIjpbIjE2NzA3NzY4MDIwMDE5MDQ5ODUxODAzNjk1NjE2MDAwNjk5OTUzMjEwMjg3MDk1MDU1Nzk3NjMzMjU0MzE2MDM1NTQ4NzkxODg2OTk2IiwiMjA4NTkxOTk5NDkxMDAzMzg5MzI4MDUwNTA2NTQ3ODcwNjAxMDQwMTUxNjEzODg5ODQ3ODEyNTUxNjk1MjcxMDU2MzM4ODQ0MjA2ODciLCIxIl0sInByb3RvY29sIjoiZ3JvdGgxNiIsImN1cnZlIjoiYm4xMjgifSwicHViX3NpZ25hbHMiOlsiMzc5OTQ5MTUwMTMwMjE0NzIzNDIwNTg5NjEwOTExMTYxODk1NDk1NjQ3Nzg5MDA2NjQ5Nzg1MjY0NzM4MTQxMjk5MTM1NDE0MjcyIiwiMTg2NTYxNDc1NDY2NjY5NDQ0ODQ0NTM4OTkyNDE5MTY0Njk1NDQwOTAyNTg4MTAxOTI4MDM5NDk1MjI3OTQ0OTA0OTMyNzEwMDUzMTMiLCIxIiwiMTczMzkyNzA2MjQzMDcwMDY1MjI4Mjk1ODc1NzA0MDIxMjg4MjUxNDc4NDU3NDQ2MDE3ODA2ODkyNTgwMzM2MjMwNTY0MDU5MzM3MDYiLCIyNjU5OTcwNzAwMjQ2MDE0NDM3OTA5Mjc1NTM3MDM4NDYzNTQ5NjU2MzgwNzQ1Mjg3ODk4OTE5MjM1MjYyNzI3MTc2ODM0MjUyOCIsIjE2NDIwNzQzNjIiLCIxMDY1OTA4ODAwNzMzMDM0MTg4MTg0OTA3MTA2Mzk1NTY3MDQ0NjIiLCIyIiwiNSIsIjg0MCIsIjEyMCIsIjM0MCIsIjUwOSIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCJdfV19fQ.eyJwcm9vZiI6eyJwaV9hIjpbIjMwMTc3ODIzODI1MzEwODkxMzY0NzgzNjU4MjAzMDMwNDY1NDkyMDYwMjA5MzEyNjc0NjgwNzk4NzY2ODM5NDE5MjcxMDgyNDkxNDEiLCI0OTAyMzUzODc4OTI0MTk2NzUyMTI2NDY2MTczMTM3NjQ0MjE4MDY2MTY0MDE5ODc4NDM4MzU3MDc0NDkwNjU4MTY2MjUyNTMxMzIxIiwiMSJdLCJwaV9iIjpbWyIxMjExNDEwOTAwNzkxMDg1NjM1MTk4ODgxNzQ0MjY1NTE3NjY3NTQ0OTE5NDcyOTc4MzYyNjQxNjUyMjY5NjAwMTA1NjIyMjA1MDA3NCIsIjE3NzIyMDA5NDMxNjI0MzUwMDAzMTU4MjgwOTcxNzk1NDQ2NTgwMzkxNTIzOTY3NzYxMzI4MzIzNjU4NDgxMTc2NDM3MTYxNzkxOTU2Il0sWyIxNzYyMzU3NzEzMzgzNzU4MDEzNzY4MDQ3NDQwNzk2NjY5OTA5Nzc0MDQxMzk1ODkxNzU2Njc0ODE4OTQ3OTM0NDQ2OTY5MTY1MDUyOCIsIjIxNDg2ODU3NDI2OTU4NTgxNzE4MjYwNDU4NzgyMjUxMjUwNzcwNTg0NzU0NzkyMDc4MTIwNDA0NzM3NDkzNzI3Njg1NTg3MjExNjM0Il0sWyIxIiwiMCJdXSwicGlfYyI6WyIxNjY4OTYyNDQ2ODc3MTI5MTc0MDY1MzY2MjczMjYxNzQzODEyODAwMzc2NzQyNDUwMDI0NjIyODI3NjA3MTYzMDI5NjQ4MjUxNTM0NiIsIjE1NDI3MzQxMDYxNzcxNDYyNjI1OTg3NjkzNzI4NjY0Njk0MTA0Mzk0OTcxNjE5NzUyOTk2NjUyNTQ2OTkzNzEwNjM5MDQ3NzMzNjE4IiwiMSJdLCJwcm90b2NvbCI6Imdyb3RoMTYifSwicHViX3NpZ25hbHMiOlsiODQ5NTg4MzgyMTE1NzY5NjE2MjY1NDAzNDE4MDIwNjk2OTU1NjYxNTQ5NzgxOTM2Mzc4OTc4NTUyMTI4MzQ5OTk3MDQ4MTk4MDk0MCIsIjE4NjU2MTQ3NTQ2NjY2OTQ0NDg0NDUzODk5MjQxOTE2NDY5NTQ0MDkwMjU4ODEwMTkyODAzOTQ5NTIyNzk0NDkwNDkzMjcxMDA1MzEzIiwiMzc5OTQ5MTUwMTMwMjE0NzIzNDIwNTg5NjEwOTExMTYxODk1NDk1NjQ3Nzg5MDA2NjQ5Nzg1MjY0NzM4MTQxMjk5MTM1NDE0MjcyIl19`

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
								"1886918534832719851890321463403403984129131165546634145956170501591930441217",
								"6655579421620637446732087343801770832201862323895906495279402105137977303781",
								"1",
							},
							B: [][]string{
								{
									"9169079072239264579542136478120546648602417723883575380902565713898445847407",
									"19892529896743597497143526216812621221702441646677187616198045140410139604850",
								},
								{
									"2227131843642265252863230630671907130727822896030596855045908403574129004371",
									"11206781133823943671644452813496911200888630423721769626699105815720196027761",
								},
								{
									"1",
									"0",
								}},
							C: []string{
								"4939638222702977380323761508903944673657041168500738909686531050713946789170",
								"9393906835076280711459107422291218224824322615260507505878201886261132992290",
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
