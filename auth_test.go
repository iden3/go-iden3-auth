package auth

import (
	"context"
	"encoding/json"
	"fmt"
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
							"17300412240859444515392568163435804813017976692285923296472945635331932727680",
							"7987339170212675259821816067019157877322619530773523635442853691144276581175",
							"1",
						},
						B: [][]string{
							{
								"5486219459376127769845397505363323827097781846702616106528032766863904141460",
								"11039278958960874345161114839879155843571258672217556129876164981000000213181",
							},
							{
								"5734177967798447984375578254489289977886713350854096962368592857583115164274",
								"21771665105082077940581255424279921654694357633832951123887813648180657619621",
							},
							{
								"1",
								"0",
							}},
						C: []string{
							"4106769399781383134298643763906436588385207522345794758381044448953462017859",
							"1234974648670414565564350118653247493464081700953044140002324628423327393314",
							"1",
						},
						Protocol: "groth16",
					},
					PubSignals: []string{
						"26599593799728934680860584327714016459626247438431721735682191132926148608",
						"4418769696461428246512928789643504202311642636963003365499223889989622854438",
						"12345",
						"16446163964048470129035485707706889290749894786011731450838224817103550600055",
						"77831441471838426779291891106433475666842073117835485972167846259714555904",
						"1653653936",
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

	rb, _ := json.Marshal(request)
	t.Log(string(rb))

	mb, _ := json.Marshal(message)
	t.Log(string(mb))

	authInstance := Verifier{verificationKeyloader, schemaLoader, stateResolver}
	err := authInstance.VerifyAuthResponse(context.Background(), message, request)
	assert.Nil(t, err)

}

func TestVerifyMessageBasicAuth(t *testing.T) {

	verifierID := "1125GJqgw6YEsKFwj63GY87MMxPL9kwDKxPUiwMLNZ"
	callbackURL := "https://test.com/callback"
	reason := "basic auth"

	request := CreateAuthorizationRequestWithMessage(reason, "msg", verifierID, callbackURL)

	b, _ := json.Marshal(request)
	fmt.Println(string(b))
	// response

	userID := "1125GJqgw6YEsKFwj63GY87MMxPL9kwDKxPUiwMLNZ"
	responseUUID := uuid.New()

	var message protocol.AuthorizationResponseMessage
	message.Typ = packers.MediaTypePlainMessage
	message.Type = protocol.AuthorizationResponseMessageType
	message.From = userID
	message.To = verifierID
	message.ID = responseUUID.String()
	message.ThreadID = request.ThreadID
	message.Body = protocol.AuthorizationMessageResponseBody{
		Scope:   []protocol.ZeroKnowledgeProofResponse{},
		Message: "msg",
	}

	authInstance := Verifier{verificationKeyloader, schemaLoader, stateResolver}
	err := authInstance.VerifyAuthResponse(context.Background(), message, request)
	assert.Nil(t, err)
}

func TestVerifier_VerifyJWZ(t *testing.T) {

	token := `eyJhbGciOiJncm90aDE2IiwiY2lyY3VpdElkIjoiYXV0aCIsImNyaXQiOlsiY2lyY3VpdElkIl0sInR5cCI6IkpXWiJ9.eyJpZCI6IjI4NDk0MDA3LTljNDktNGYxYS05Njk0LTc3MDBjMDg4NjViZiIsInR5cCI6ImFwcGxpY2F0aW9uL2lkZW4zY29tbS1wbGFpbi1qc29uIiwidHlwZSI6Imh0dHBzOi8vaWRlbjMtY29tbXVuaWNhdGlvbi5pby9hdXRob3JpemF0aW9uLzEuMC9yZXNwb25zZSIsInRoaWQiOiI3ZjM4YTE5My0wOTE4LTRhNDgtOWZhYy0zNmFkZmRiOGI1NDIiLCJib2R5Ijp7Im1lc3NhZ2UiOiJtZXNzYWdlIHRvIHNpZ24iLCJzY29wZSI6W3siaWQiOjEsImNpcmN1aXRfaWQiOiJjcmVkZW50aWFsQXRvbWljUXVlcnlNVFAiLCJwcm9vZiI6eyJwaV9hIjpbIjIwOTczNDg1MTA3MTg2NjEzODM1Mjk0NDIwNTA0MTY4ODQ0OTAwMDYwNDI5NzQ1MTgwMjc3MzcwMDc4MTM2NjQ1NDIzMzIzNzk2OTg4IiwiMjA4NzY1MTIzNTU1MTc0NTQzNTgzODczNTIzNTc0MzA0NjkyNjk1MzI1MTEyMDg0Mjc3MDI0MzU2NDA5NTQyMTI0MTQ4NDY3OTQ5ODgiLCIxIl0sInBpX2IiOltbIjE1MzU5Nzg3NzkyMjkxMzAxNTI0NDI5NTExNTYzMTYzODE5ODMzMjA5NjcwNTg2ODkxNDk5MTQ5ODgwMTAzODk3ODIxNjMxODEyMzIwIiwiOTUyMTQ4MDk3NzQxMzE4NzUwNDAxNDA2Njc4MjQ4ODY0NDgyNDA4MTEzNDE4NzI4MDQ1NTQxODUzMjU0ODM4NzkwMjExOTQ0NTU3Il0sWyIzODY2NTQ3MDY4OTg4Mzc4NDE5Nzg3MjE2NDk0ODUwNDQxOTM3MzkzNzQ4ODQ5ODU5NDExNjE5OTk1MDMwMDkxNjY2Njc4MjM0MjMzIiwiMTI3MzcyNjA5NTQ5ODM3NzIwNDc2ODA0Mzc5NDExOTM2NzU4ODYyMTUzMTU0NjM5NjUwOTk1MjcyMTUzNTQ0Mjg4NTYxNjY1ODkyMjAiXSxbIjEiLCIwIl1dLCJwaV9jIjpbIjE0MDMyMDUxNjY5Mzc2NTE5OTMyOTU3MDcyMTQ3MzgyNzM5MTM0NjU4ODg1NzgyNjYxMzkwMTcwNjU4NjMxMTA3Nzk1Mzg2MDM0OTkwIiwiMzQyNjY1MTkyMDE2ODU3NjE0MTMyODQ2NjQ0MTM4NTg3Mjg5NDgyNDQxNzE0MTc4ODI2MDgzMDgzMjU2MzcwNzk1MDYwNTAzNDU0MiIsIjEiXSwicHJvdG9jb2wiOiJncm90aDE2In0sInB1Yl9zaWduYWxzIjpbIjIyNzk5OTc5MjU2MDYwMTU4MTE0MzkyMzEyMTIxMDM4ODM4MjE5ODI3NjgyODkzMjExMjIzNzc0MjMxOTE1MzcwOTI3NDIzNDg4MCIsIjEwMDk5Nzg5NjY1MzAwOTc1NDU3ODAyMTc4ODYyMjk2MDk4MjcxMjQzMzU5NjYwMzE1ODAyNzU5NDk1MDE2Mjg1MzUyNjQwMjEyODE0IiwiMTIzNDUiLCI4MzkwNzk1NjU0NzM5MjAzOTcyNjE2OTI2Nzc0MDkxNDQ1NDk4NDUxNTIwODEzMTQyMTIxMzY1Njc4NTY1MTM2MjI4NTI4NzI1MzEyIiwiMjA2ODExNzkxNDMxMjY5NzA3NDI3NTg5MzAyMjc0OTUyNDczMTQ3ODc5ODg4MDIyMTQyMDk2MzYzOTUwNDY1NjU2MDE0MTEwNzIwIiwiMTY1MzA1NzA2MiIsIjEwNjU5MDg4MDA3MzMwMzQxODgxODQ5MDcxMDYzOTU1NjcwNDQ2MiIsIjIiLCI0IiwiODQwIiwiMTIwIiwiMzQwIiwiNTA5IiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIl19XX0sImZyb20iOiIxMTl0cWNlV2RSZDJGNlduQXlWdUZRUkZqSzNXVVhxMkxvclNQeUc5TEoiLCJ0byI6IjExMjVHSnFndzZZRXNLRndqNjNHWTg3TU14UEw5a3dES3hQVWl3TUxOWiJ9.eyJwcm9vZiI6eyJwaV9hIjpbIjc3MTc5OTI2ODcwMTg3NzAxMjE2Nzg5OTMwNjE3OTU4OTE2NTM5MzkyOTY2NzE3MTA5NjA0NzQwMDI0NjMyNTI4NzI2ODM4NDAyNzAiLCIxNDY3MjQyOTIzNDg0MzUxMzkwNDM1NzEyOTk4MzEwNDU0MjU4OTY5NDc3ODYzMzMxMzk3NTM0NDgwNTY1ODA3MjQ3ODcwNzc5Mjg2OSIsIjEiXSwicGlfYiI6W1siOTU1MDE3NjEzNjE0NTc5NTM3MDU5MjEzMTMyNzE5NDgxMjI2NjMyMjA5ODAxODY2MTM2MDk4MDgyMTM4NzY2MTg5NDc0NTc0ODA5NiIsIjIwODA2MDgxOTg0NDk3MDc0NDEyNDI3NjMwNzg4OTU3MTQ2MzUwNTY0NDE2NjA4ODkyODAxOTAyMDkzOTY5MTUwODM1NzY3MjAzMDIyIl0sWyIzMTQwNzY0NzMyMDA3NjYxODAwMjc1MzEzNjcwNzI0Njc0NTcyNjE2NjYxNTI1MzU5NzgxNDg3NjgzMjA3MTg0OTY5OTE0MjUxMjc4IiwiMjQ4NTU1MzI0OTQ5NTk0MTUyNzU3NTY5MjU4MTY2NDMyNzU1NDk3OTMwMDg2NTgxNjAzNDAyNjI5MTM2MDIyODYyMDQ5NjA1ODY4OCJdLFsiMSIsIjAiXV0sInBpX2MiOlsiMjA2OTA1NjkzMTM5MjgxNDgzMzIwMzA2MjM4OTMzMTE4MTg5ODQzNTk5OTg3NTk0NTgxNzc1MjY5NTY3NDgwNzA2NjExMjcyNjE1OTYiLCI4ODkzNTY5NjgxOTI4ODEyNTQyNTc5ODIwNjI4NDM3ODY4Njk1MDkzMDE5NTI2ODIxMDQ2NDA0MTk4ODMxNjkyMjU0NTA0OTEzMTQ3IiwiMSJdLCJwcm90b2NvbCI6Imdyb3RoMTYifSwicHViX3NpZ25hbHMiOlsiMzUyNjc2ODY1MTAyMDM5MDU5NDUxOTI1NTY2MDQ2MTU2NzAwNzE0NDkxMDY1MDk0ODYzNDA4NzI3NjQzNTc0ODUzNDQ0ODc0ODMzNSIsIjE4NjU2MTQ3NTQ2NjY2OTQ0NDg0NDUzODk5MjQxOTE2NDY5NTQ0MDkwMjU4ODEwMTkyODAzOTQ5NTIyNzk0NDkwNDkzMjcxMDA1MzEzIiwiMzc5OTQ5MTUwMTMwMjE0NzIzNDIwNTg5NjEwOTExMTYxODk1NDk1NjQ3Nzg5MDA2NjQ5Nzg1MjY0NzM4MTQxMjk5MTM1NDE0MjcyIl19`

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

	token := `eyJhbGciOiJncm90aDE2IiwiY2lyY3VpdElkIjoiYXV0aCIsImNyaXQiOlsiY2lyY3VpdElkIl0sInR5cCI6IkpXWiJ9.eyJpZCI6IjI4NDk0MDA3LTljNDktNGYxYS05Njk0LTc3MDBjMDg4NjViZiIsInR5cCI6ImFwcGxpY2F0aW9uL2lkZW4zY29tbS1wbGFpbi1qc29uIiwidHlwZSI6Imh0dHBzOi8vaWRlbjMtY29tbXVuaWNhdGlvbi5pby9hdXRob3JpemF0aW9uLzEuMC9yZXNwb25zZSIsInRoaWQiOiI3ZjM4YTE5My0wOTE4LTRhNDgtOWZhYy0zNmFkZmRiOGI1NDIiLCJib2R5Ijp7Im1lc3NhZ2UiOiJtZXNzYWdlIHRvIHNpZ24iLCJzY29wZSI6W3siaWQiOjEsImNpcmN1aXRfaWQiOiJjcmVkZW50aWFsQXRvbWljUXVlcnlNVFAiLCJwcm9vZiI6eyJwaV9hIjpbIjE3MzAwNDEyMjQwODU5NDQ0NTE1MzkyNTY4MTYzNDM1ODA0ODEzMDE3OTc2NjkyMjg1OTIzMjk2NDcyOTQ1NjM1MzMxOTMyNzI3NjgwIiwiNzk4NzMzOTE3MDIxMjY3NTI1OTgyMTgxNjA2NzAxOTE1Nzg3NzMyMjYxOTUzMDc3MzUyMzYzNTQ0Mjg1MzY5MTE0NDI3NjU4MTE3NSIsIjEiXSwicGlfYiI6W1siNTQ4NjIxOTQ1OTM3NjEyNzc2OTg0NTM5NzUwNTM2MzMyMzgyNzA5Nzc4MTg0NjcwMjYxNjEwNjUyODAzMjc2Njg2MzkwNDE0MTQ2MCIsIjExMDM5Mjc4OTU4OTYwODc0MzQ1MTYxMTE0ODM5ODc5MTU1ODQzNTcxMjU4NjcyMjE3NTU2MTI5ODc2MTY0OTgxMDAwMDAwMjEzMTgxIl0sWyI1NzM0MTc3OTY3Nzk4NDQ3OTg0Mzc1NTc4MjU0NDg5Mjg5OTc3ODg2NzEzMzUwODU0MDk2OTYyMzY4NTkyODU3NTgzMTE1MTY0Mjc0IiwiMjE3NzE2NjUxMDUwODIwNzc5NDA1ODEyNTU0MjQyNzk5MjE2NTQ2OTQzNTc2MzM4MzI5NTExMjM4ODc4MTM2NDgxODA2NTc2MTk2MjEiXSxbIjEiLCIwIl1dLCJwaV9jIjpbIjQxMDY3NjkzOTk3ODEzODMxMzQyOTg2NDM3NjM5MDY0MzY1ODgzODUyMDc1MjIzNDU3OTQ3NTgzODEwNDQ0NDg5NTM0NjIwMTc4NTkiLCIxMjM0OTc0NjQ4NjcwNDE0NTY1NTY0MzUwMTE4NjUzMjQ3NDkzNDY0MDgxNzAwOTUzMDQ0MTQwMDAyMzI0NjI4NDIzMzI3MzkzMzE0IiwiMSJdLCJwcm90b2NvbCI6Imdyb3RoMTYifSwicHViX3NpZ25hbHMiOlsiMjY1OTk1OTM3OTk3Mjg5MzQ2ODA4NjA1ODQzMjc3MTQwMTY0NTk2MjYyNDc0Mzg0MzE3MjE3MzU2ODIxOTExMzI5MjYxNDg2MDgiLCI0NDE4NzY5Njk2NDYxNDI4MjQ2NTEyOTI4Nzg5NjQzNTA0MjAyMzExNjQyNjM2OTYzMDAzMzY1NDk5MjIzODg5OTg5NjIyODU0NDM4IiwiMTIzNDUiLCIxNjQ0NjE2Mzk2NDA0ODQ3MDEyOTAzNTQ4NTcwNzcwNjg4OTI5MDc0OTg5NDc4NjAxMTczMTQ1MDgzODIyNDgxNzEwMzU1MDYwMDA1NSIsIjc3ODMxNDQxNDcxODM4NDI2Nzc5MjkxODkxMTA2NDMzNDc1NjY2ODQyMDczMTE3ODM1NDg1OTcyMTY3ODQ2MjU5NzE0NTU1OTA0IiwiMTY1MzY1MzkzNiIsIjEwNjU5MDg4MDA3MzMwMzQxODgxODQ5MDcxMDYzOTU1NjcwNDQ2MiIsIjIiLCI1IiwiODQwIiwiMTIwIiwiMzQwIiwiNTA5IiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIl19XX0sImZyb20iOiIxMTl0cWNlV2RSZDJGNlduQXlWdUZRUkZqSzNXVVhxMkxvclNQeUc5TEoiLCJ0byI6IjExMjVHSnFndzZZRXNLRndqNjNHWTg3TU14UEw5a3dES3hQVWl3TUxOWiJ9.eyJwcm9vZiI6eyJwaV9hIjpbIjEyNTU0NzU3NDQ1NTg5OTUxNDU2NTgzMzI0OTYzNTI1NTA4NjUyNjE0NjQ3ODA3Mjk1NzI1MzQ4NzEyNjUxNDgyNjU4NjEwNjYxMzIzIiwiODM0MzQ0Mjc4OTQxOTA0MTk5MDYzMTEzNjYyMTY5MzAyMzIzNDM1OTA0NTc0NDY1MDU1NzEyODc2MjgwMTQ1NTM5MTg0ODI5MDQ5NSIsIjEiXSwicGlfYiI6W1siNTM4NzcwMDMxNjE4OTE2MzY0MDIwODIxODUyMDM4OTY3NjY2NTc3MDUzMDE0NjM3MjMyMDkwNzc1ODg3MzQ3MzQxMTM2MzYxOTEyNyIsIjgxMjk1MzM5OTEzMjA3ODY0NzMwNDUxMTY5NTkzNjY2OTk1MTcyMjIxMjg1NDY1MzEyMjc3MDA3NTg3OTYxODU1ODY1ODk4OTIxMzMiXSxbIjEwODc3NjczNjU1MDQyNTAwNTIzNTQzNTMyMTMyMzg1MDUzOTI5OTY4Njc3NTU3NTI2MjY1NDcwNTQ1NTU5NDQ1MjcwMzUwNDM5MDczIiwiMjY5MDMyOTcyNjkyOTcyMzcwMjc5MzE3ODI4MzEzMTI5MzY2NzE2MjQ4OTIwMjQwMTA0OTUwNzgwMTUyMTc3MDgwMzQ3MzYxMTU3MSJdLFsiMSIsIjAiXV0sInBpX2MiOlsiMjA5OTA5Nzg3MTY4OTU5OTA5NjY2ODEwMDk2ODQxNDc0MTY5NDk5MjM0ODMyNjI2NTkzMTYwNDk0MDk1NjA4MzgwNTYwMzI5ODk1NDkiLCI1NDA5ODkxODEwMTQxNjY1MzM4NTMwNjk1MDczNzg0MzIwMTgzMDc1NzMyMDUxOTYyOTI5Mjc1MTY3MzQzMjM5OTc5NzQwODQ4MTY4IiwiMSJdLCJwcm90b2NvbCI6Imdyb3RoMTYifSwicHViX3NpZ25hbHMiOlsiNjIwMTgwNzQyMjkzNTQ0MzAzOTMzMjQ2Mzc3NTQyNzYzNzE3ODkxMTgwMjU5NTExNjI1MjEwNjQ5NTgzMzA0MzI5NjgwMDU3NDE4NSIsIjE4NjU2MTQ3NTQ2NjY2OTQ0NDg0NDUzODk5MjQxOTE2NDY5NTQ0MDkwMjU4ODEwMTkyODAzOTQ5NTIyNzk0NDkwNDkzMjcxMDA1MzEzIiwiMzc5OTQ5MTUwMTMwMjE0NzIzNDIwNTg5NjEwOTExMTYxODk1NDk1NjQ3Nzg5MDA2NjQ5Nzg1MjY0NzM4MTQxMjk5MTM1NDE0MjcyIl19`

	authInstance := Verifier{verificationKeyloader, schemaLoader, stateResolver}
	_, err := authInstance.FullVerify(context.Background(), token, request)
	assert.Nil(t, err)
}

func TestVerifyAuthResponseWithEmptyReq(t *testing.T) {

	verifierID := "1125GJqgw6YEsKFwj63GY87MMxPL9kwDKxPUiwMLNZ"
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
				Type: "KYCAgeCredential",
			},
		},
	}

	authReq := CreateAuthorizationRequestWithMessage(reason, "test", verifierID, callbackURL)
	authReq.Body.Scope = append(authReq.Body.Scope, zkReq)
	authReq.ID = "28494007-9c49-4f1a-9694-7700c08865bf"
	authReq.ThreadID = "https://iden3-communication.io/authorization/1.0/response"

	// response
	resp := protocol.AuthorizationResponseMessage{
		ID:       "1",
		Typ:      "application/iden3comm-plain-json",
		Type:     "https://iden3-communication.io/authorization/1.0/response",
		ThreadID: "https://iden3-communication.io/authorization/1.0/response",
		Body: protocol.AuthorizationMessageResponseBody{
			Message: "test",
			Scope: []protocol.ZeroKnowledgeProofResponse{
				{
					ID:        1,
					CircuitID: string(circuits.AtomicQueryMTPCircuitID),
					ZKProof: types.ZKProof{
						Proof: &types.ProofData{
							A: []string{
								"8129021067857370158336933234117611015600824496598483591445329001248490395443",
								"11022760058510341476521360145694321967709384053025093704762597148489064373638",
								"1",
							},
							B: [][]string{
								{
									"17224572865776547150980923580315029213385775952907276202502483864558678953663",
									"7916279123157975555411382729686184762096420253088685039153782781632846163766",
								},
								{
									"6543245356971224930497639142818108733047706738450918502204752818814477036872",
									"7268871353151170880968746267918865208566079097761521626638709867882376350103",
								},
								{
									"1",
									"0",
								}},
							C: []string{
								"21861157196621814667592503349594312848178766348003966276013143339656490164756",
								"4116459748076407277103067699923461691822133527399128436612609523462069568515",
								"1",
							},
							Protocol: "groth16",
						},
						PubSignals: []string{
							"418819142901396254645139402764555295161415578968331917453536578713848119296",
							"7874203532978883949027009733018606841554651695391205748574631039716853542278",
							"12345",
							"488733818752713055856387510875443500707327158339343858367993664412380846187",
							"397645406062664346390412961521324012658320993428910364781714672838217564160",
							"1653682203",
							"210459579859058135404770043788028292398",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
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
		From: "119tqceWdRd2F6WnAyVuFQRFjK3WUXq2LorSPyG9LJ",
		To:   "1125GJqgw6YEsKFwj63GY87MMxPL9kwDKxPUiwMLNZ",
	}

	authInstance := Verifier{verificationKeyloader, schemaLoader, stateResolver}
	err := authInstance.VerifyAuthResponse(context.Background(), resp, authReq)
	assert.NoError(t, err)
}
