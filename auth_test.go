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
	request.ID = "7f38a193-0918-4a48-9fac-36adfdb8b542"
	request.ThreadID = "7f38a193-0918-4a48-9fac-36adfdb8b542" // because it's used in the response

	token := `eyJhbGciOiJncm90aDE2IiwiY2lyY3VpdElkIjoiYXV0aCIsImNyaXQiOlsiY2lyY3VpdElkIl0sInR5cCI6ImFwcGxpY2F0aW9uL2lkZW4zLXprcC1qc29uIn0.eyJpZCI6IjI4NDk0MDA3LTljNDktNGYxYS05Njk0LTc3MDBjMDg4NjViZiIsInR5cCI6ImFwcGxpY2F0aW9uL2lkZW4zY29tbS1wbGFpbi1qc29uIiwidHlwZSI6Imh0dHBzOi8vaWRlbjMtY29tbXVuaWNhdGlvbi5pby9hdXRob3JpemF0aW9uLzEuMC9yZXNwb25zZSIsInRoaWQiOiI3ZjM4YTE5My0wOTE4LTRhNDgtOWZhYy0zNmFkZmRiOGI1NDIiLCJib2R5Ijp7Im1lc3NhZ2UiOiJtZXNzYWdlIHRvIHNpZ24iLCJzY29wZSI6W3siaWQiOjEsImNpcmN1aXRfaWQiOiJjcmVkZW50aWFsQXRvbWljUXVlcnlNVFAiLCJwcm9vZiI6eyJwaV9hIjpbIjIwOTczNDg1MTA3MTg2NjEzODM1Mjk0NDIwNTA0MTY4ODQ0OTAwMDYwNDI5NzQ1MTgwMjc3MzcwMDc4MTM2NjQ1NDIzMzIzNzk2OTg4IiwiMjA4NzY1MTIzNTU1MTc0NTQzNTgzODczNTIzNTc0MzA0NjkyNjk1MzI1MTEyMDg0Mjc3MDI0MzU2NDA5NTQyMTI0MTQ4NDY3OTQ5ODgiLCIxIl0sInBpX2IiOltbIjE1MzU5Nzg3NzkyMjkxMzAxNTI0NDI5NTExNTYzMTYzODE5ODMzMjA5NjcwNTg2ODkxNDk5MTQ5ODgwMTAzODk3ODIxNjMxODEyMzIwIiwiOTUyMTQ4MDk3NzQxMzE4NzUwNDAxNDA2Njc4MjQ4ODY0NDgyNDA4MTEzNDE4NzI4MDQ1NTQxODUzMjU0ODM4NzkwMjExOTQ0NTU3Il0sWyIzODY2NTQ3MDY4OTg4Mzc4NDE5Nzg3MjE2NDk0ODUwNDQxOTM3MzkzNzQ4ODQ5ODU5NDExNjE5OTk1MDMwMDkxNjY2Njc4MjM0MjMzIiwiMTI3MzcyNjA5NTQ5ODM3NzIwNDc2ODA0Mzc5NDExOTM2NzU4ODYyMTUzMTU0NjM5NjUwOTk1MjcyMTUzNTQ0Mjg4NTYxNjY1ODkyMjAiXSxbIjEiLCIwIl1dLCJwaV9jIjpbIjE0MDMyMDUxNjY5Mzc2NTE5OTMyOTU3MDcyMTQ3MzgyNzM5MTM0NjU4ODg1NzgyNjYxMzkwMTcwNjU4NjMxMTA3Nzk1Mzg2MDM0OTkwIiwiMzQyNjY1MTkyMDE2ODU3NjE0MTMyODQ2NjQ0MTM4NTg3Mjg5NDgyNDQxNzE0MTc4ODI2MDgzMDgzMjU2MzcwNzk1MDYwNTAzNDU0MiIsIjEiXSwicHJvdG9jb2wiOiJncm90aDE2In0sInB1Yl9zaWduYWxzIjpbIjIyNzk5OTc5MjU2MDYwMTU4MTE0MzkyMzEyMTIxMDM4ODM4MjE5ODI3NjgyODkzMjExMjIzNzc0MjMxOTE1MzcwOTI3NDIzNDg4MCIsIjEwMDk5Nzg5NjY1MzAwOTc1NDU3ODAyMTc4ODYyMjk2MDk4MjcxMjQzMzU5NjYwMzE1ODAyNzU5NDk1MDE2Mjg1MzUyNjQwMjEyODE0IiwiMTIzNDUiLCI4MzkwNzk1NjU0NzM5MjAzOTcyNjE2OTI2Nzc0MDkxNDQ1NDk4NDUxNTIwODEzMTQyMTIxMzY1Njc4NTY1MTM2MjI4NTI4NzI1MzEyIiwiMjA2ODExNzkxNDMxMjY5NzA3NDI3NTg5MzAyMjc0OTUyNDczMTQ3ODc5ODg4MDIyMTQyMDk2MzYzOTUwNDY1NjU2MDE0MTEwNzIwIiwiMTY1MzA1NzA2MiIsIjEwNjU5MDg4MDA3MzMwMzQxODgxODQ5MDcxMDYzOTU1NjcwNDQ2MiIsIjIiLCI0IiwiODQwIiwiMTIwIiwiMzQwIiwiNTA5IiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIl19XX0sImZyb20iOiIxMTl0cWNlV2RSZDJGNlduQXlWdUZRUkZqSzNXVVhxMkxvclNQeUc5TEoiLCJ0byI6IjExMjVHSnFndzZZRXNLRndqNjNHWTg3TU14UEw5a3dES3hQVWl3TUxOWiJ9.eyJwcm9vZiI6eyJwaV9hIjpbIjEwNDEyNDM2MTk3NDk0NDc5NTg3Mzk2NjY3Mzg1NzA3MzY4MjgyNTY4MDU1MTE4MjY5ODY0NDU3OTI3NDc2OTkwNjM2NDE5NzAyNDUxIiwiMTA3ODE3MzkwOTU0NDUyMDE5OTY0Njc0MTQ4MTc5NDE4MDU4Nzk5ODI0MTA2NzYzODYxNzY4NDUyOTYzNzYzNDQ5ODUxODc2NjMzMzQiLCIxIl0sInBpX2IiOltbIjE4MDY3ODY4NzQwMDA2MjI1NjE1NDQ3MTk0NDcxMzcwNjU4OTgwOTk5OTI2MzY5Njk1MjkzMTE1NzEyOTUxMzY2NzA3NzQ0MDY0NjA2IiwiMjE1OTkyNDE1NzA1NDc3MzEyMzQzMDQwMzk5ODkxNjY0MDY0MTU4OTk3MTc2NTkxNzE3NjAwNDM4OTk1MDkxNTIwMTE0Nzk2NjM3NTciXSxbIjY2OTk1NDA3MDUwNzQ5MjQ5OTc5NjcyNzUxODYzMjQ3NTU0NDIyNjA2MDc2NzE1MzY0MzQ0MDMwNjU1MjkxNjQ3Njk3MDI0NzczOTgiLCIxMTI1NzY0MzI5MzIwMTYyNzQ1MDI5MzE4NTE2NDI4ODQ4MjQyMDU1OTgwNjY0OTkzNzM3MTU2ODE2MDc0MjYwMTM4NjY3MTY1OTgwMCJdLFsiMSIsIjAiXV0sInBpX2MiOlsiNjIxNjQyMzUwMzI4OTQ5NjI5Mjk0NDA1MjAzMjE5MDM1MzYyNTQyMjQxMTQ4MzM4MzM3ODk3OTAyOTY2NzI0Mzc4NTMxOTIwODA5NSIsIjE0ODE2MjE4MDQ1MTU4Mzg4NzU4NTY3NjA4NjA1NTc2Mzg0OTk0MzM5NzE0MzkwMzcwMzAwOTYzNTgwNjU4Mzg2NTM0MTU4NjAzNzExIiwiMSJdLCJwcm90b2NvbCI6Imdyb3RoMTYifSwicHViX3NpZ25hbHMiOlsiNDk3Njk0Mzk0Mzk2NjM2NTA2MjEyMzIyMTk5OTgzODAxMzE3MTIyODE1NjQ5NTM2NjI3MDM3NzI2MTM4MDQ0OTc4Nzg3MTg5ODY3MiIsIjE4NjU2MTQ3NTQ2NjY2OTQ0NDg0NDUzODk5MjQxOTE2NDY5NTQ0MDkwMjU4ODEwMTkyODAzOTQ5NTIyNzk0NDkwNDkzMjcxMDA1MzEzIiwiMzc5OTQ5MTUwMTMwMjE0NzIzNDIwNTg5NjEwOTExMTYxODk1NDk1NjQ3Nzg5MDA2NjQ5Nzg1MjY0NzM4MTQxMjk5MTM1NDE0MjcyIl19`

	authInstance := Verifier{verificationKeyloader, schemaLoader, stateResolver}
	_, err := authInstance.FullVerify(context.Background(), token, request)
	assert.Nil(t, err)
}
