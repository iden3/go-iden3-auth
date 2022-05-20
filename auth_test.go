package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/gofrs/uuid"
	"github.com/iden3/go-iden3-auth/pubsignals"
	"github.com/iden3/go-iden3-auth/state"
	"github.com/iden3/go-rapidsnark/types"
	"github.com/iden3/iden3comm/packers"
	"github.com/iden3/iden3comm/protocol"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"

	"github.com/iden3/go-circuits"
)

type FileKeyLoader struct {
}

func (l *FileKeyLoader) Load(id circuits.CircuitID) ([]byte, error) {
	switch id {
	case circuits.AtomicQueryMTPCircuitID:
		return os.ReadFile("testdata/mtpVerificationKey.json")

	case circuits.AuthCircuitID:
		return os.ReadFile("testdata/authVerificationKey.json")
	}
	return []byte{}, nil
}

func TestCreateAuthorizationRequest(t *testing.T) {

	sender := "1125GJqgw6YEsKFwj63GY87MMxPL9kwDKxPUiwMLNZ"
	callbackURL := "https://test.com/callback"
	reason := "basic authentication"

	request, err := CreateAuthorizationRequest(reason, sender, callbackURL)
	assert.NoError(t, err)
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

	request, err := CreateAuthorizationRequest(reason, sender, callbackURL)
	assert.NoError(t, err)
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
	request, err := CreateAuthorizationRequestWithMessage(reason, "message to sign", verifierID, callbackURL)
	assert.Nil(t, err)
	request.Body.Scope = append(request.Body.Scope, mtpProofRequest)

	userID := "119tqceWdRd2F6WnAyVuFQRFjK3WUXq2LorSPyG9LJ"
	responseUUID, err := uuid.NewV4()
	assert.Nil(t, err)

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
							"20973485107186613835294420504168844900060429745180277370078136645423323796988",
							"20876512355517454358387352357430469269532511208427702435640954212414846794988",
							"1",
						},
						B: [][]string{
							{
								"15359787792291301524429511563163819833209670586891499149880103897821631812320",
								"952148097741318750401406678248864482408113418728045541853254838790211944557",
							},
							{
								"3866547068988378419787216494850441937393748849859411619995030091666678234233",
								"12737260954983772047680437941193675886215315463965099527215354428856166589220",
							},
							{
								"1",
								"0",
							}},
						C: []string{
							"14032051669376519932957072147382739134658885782661390170658631107795386034990",
							"3426651920168576141328466441385872894824417141788260830832563707950605034542",
							"1",
						},
						Protocol: "groth16",
					},
					PubSignals: []string{
						"227999792560601581143923121210388382198276828932112237742319153709274234880",
						"10099789665300975457802178862296098271243359660315802759495016285352640212814",
						"12345",
						"8390795654739203972616926774091445498451520813142121365678565136228528725312",
						"206811791431269707427589302274952473147879888022142096363950465656014110720",
						"1653057062",
						"106590880073303418818490710639556704462",
						"2",
						"4",
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

	authInstance := Verifier{&FileKeyLoader{}, state.VerificationOptions{
		Contract: "0xa36786c3e18225da7cc8fc69c6443ecd41827ff5",
		RPCUrl:   os.Getenv("RPC_URL"),
	}}
	err = authInstance.VerifyAuthResponse(context.Background(), message, *request)
	assert.Nil(t, err)

}

func TestVerifyMessageBasicAuth(t *testing.T) {

	verifierID := "1125GJqgw6YEsKFwj63GY87MMxPL9kwDKxPUiwMLNZ"
	callbackURL := "https://test.com/callback"
	reason := "basic auth"

	request, err := CreateAuthorizationRequestWithMessage(reason, "msg", verifierID, callbackURL)
	assert.Nil(t, err)

	b, _ := json.Marshal(request)
	fmt.Println(string(b))
	// response

	userID := "1125GJqgw6YEsKFwj63GY87MMxPL9kwDKxPUiwMLNZ"
	responseUUID, err := uuid.NewV4()
	assert.Nil(t, err)

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
	b, _ = json.Marshal(message)
	fmt.Println(string(b))
	authInstance := Verifier{&FileKeyLoader{}, state.VerificationOptions{
		Contract: "0xa36786c3e18225da7cc8fc69c6443ecd41827ff5",
		RPCUrl:   os.Getenv("RPC_URL"),
	}}
	err = authInstance.VerifyAuthResponse(context.Background(), message, *request)
	assert.Nil(t, err)
}

func TestVerifier_VerifyJWZ(t *testing.T) {

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
	request, err := CreateAuthorizationRequestWithMessage(reason, "message to sign", verifierID, callbackURL)
	assert.Nil(t, err)
	request.Body.Scope = append(request.Body.Scope, mtpProofRequest)
	request.ID = "7f38a193-0918-4a48-9fac-36adfdb8b542"
	request.ThreadID = "7f38a193-0918-4a48-9fac-36adfdb8b542" // because it's used in the response

	token := `eyJhbGciOiJncm90aDE2IiwiY2lyY3VpdElkIjoiYXV0aCIsImNyaXQiOlsiY2lyY3VpdElkIl0sInR5cCI6ImFwcGxpY2F0aW9uL2lkZW4zLXprcC1qc29uIn0.eyJpZCI6IjI4NDk0MDA3LTljNDktNGYxYS05Njk0LTc3MDBjMDg4NjViZiIsInR5cCI6ImFwcGxpY2F0aW9uL2lkZW4zY29tbS1wbGFpbi1qc29uIiwidHlwZSI6Imh0dHBzOi8vaWRlbjMtY29tbXVuaWNhdGlvbi5pby9hdXRob3JpemF0aW9uLzEuMC9yZXNwb25zZSIsInRoaWQiOiI3ZjM4YTE5My0wOTE4LTRhNDgtOWZhYy0zNmFkZmRiOGI1NDIiLCJib2R5Ijp7Im1lc3NhZ2UiOiJtZXNzYWdlIHRvIHNpZ24iLCJzY29wZSI6W3siaWQiOjEsImNpcmN1aXRfaWQiOiJjcmVkZW50aWFsQXRvbWljUXVlcnlNVFAiLCJwcm9vZiI6eyJwaV9hIjpbIjIwOTczNDg1MTA3MTg2NjEzODM1Mjk0NDIwNTA0MTY4ODQ0OTAwMDYwNDI5NzQ1MTgwMjc3MzcwMDc4MTM2NjQ1NDIzMzIzNzk2OTg4IiwiMjA4NzY1MTIzNTU1MTc0NTQzNTgzODczNTIzNTc0MzA0NjkyNjk1MzI1MTEyMDg0Mjc3MDI0MzU2NDA5NTQyMTI0MTQ4NDY3OTQ5ODgiLCIxIl0sInBpX2IiOltbIjE1MzU5Nzg3NzkyMjkxMzAxNTI0NDI5NTExNTYzMTYzODE5ODMzMjA5NjcwNTg2ODkxNDk5MTQ5ODgwMTAzODk3ODIxNjMxODEyMzIwIiwiOTUyMTQ4MDk3NzQxMzE4NzUwNDAxNDA2Njc4MjQ4ODY0NDgyNDA4MTEzNDE4NzI4MDQ1NTQxODUzMjU0ODM4NzkwMjExOTQ0NTU3Il0sWyIzODY2NTQ3MDY4OTg4Mzc4NDE5Nzg3MjE2NDk0ODUwNDQxOTM3MzkzNzQ4ODQ5ODU5NDExNjE5OTk1MDMwMDkxNjY2Njc4MjM0MjMzIiwiMTI3MzcyNjA5NTQ5ODM3NzIwNDc2ODA0Mzc5NDExOTM2NzU4ODYyMTUzMTU0NjM5NjUwOTk1MjcyMTUzNTQ0Mjg4NTYxNjY1ODkyMjAiXSxbIjEiLCIwIl1dLCJwaV9jIjpbIjE0MDMyMDUxNjY5Mzc2NTE5OTMyOTU3MDcyMTQ3MzgyNzM5MTM0NjU4ODg1NzgyNjYxMzkwMTcwNjU4NjMxMTA3Nzk1Mzg2MDM0OTkwIiwiMzQyNjY1MTkyMDE2ODU3NjE0MTMyODQ2NjQ0MTM4NTg3Mjg5NDgyNDQxNzE0MTc4ODI2MDgzMDgzMjU2MzcwNzk1MDYwNTAzNDU0MiIsIjEiXSwicHJvdG9jb2wiOiJncm90aDE2In0sInB1Yl9zaWduYWxzIjpbIjIyNzk5OTc5MjU2MDYwMTU4MTE0MzkyMzEyMTIxMDM4ODM4MjE5ODI3NjgyODkzMjExMjIzNzc0MjMxOTE1MzcwOTI3NDIzNDg4MCIsIjEwMDk5Nzg5NjY1MzAwOTc1NDU3ODAyMTc4ODYyMjk2MDk4MjcxMjQzMzU5NjYwMzE1ODAyNzU5NDk1MDE2Mjg1MzUyNjQwMjEyODE0IiwiMTIzNDUiLCI4MzkwNzk1NjU0NzM5MjAzOTcyNjE2OTI2Nzc0MDkxNDQ1NDk4NDUxNTIwODEzMTQyMTIxMzY1Njc4NTY1MTM2MjI4NTI4NzI1MzEyIiwiMjA2ODExNzkxNDMxMjY5NzA3NDI3NTg5MzAyMjc0OTUyNDczMTQ3ODc5ODg4MDIyMTQyMDk2MzYzOTUwNDY1NjU2MDE0MTEwNzIwIiwiMTY1MzA1NzA2MiIsIjEwNjU5MDg4MDA3MzMwMzQxODgxODQ5MDcxMDYzOTU1NjcwNDQ2MiIsIjIiLCI0IiwiODQwIiwiMTIwIiwiMzQwIiwiNTA5IiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIl19XX0sImZyb20iOiIxMTl0cWNlV2RSZDJGNlduQXlWdUZRUkZqSzNXVVhxMkxvclNQeUc5TEoiLCJ0byI6IjExMjVHSnFndzZZRXNLRndqNjNHWTg3TU14UEw5a3dES3hQVWl3TUxOWiJ9.eyJwcm9vZiI6eyJwaV9hIjpbIjEwNDEyNDM2MTk3NDk0NDc5NTg3Mzk2NjY3Mzg1NzA3MzY4MjgyNTY4MDU1MTE4MjY5ODY0NDU3OTI3NDc2OTkwNjM2NDE5NzAyNDUxIiwiMTA3ODE3MzkwOTU0NDUyMDE5OTY0Njc0MTQ4MTc5NDE4MDU4Nzk5ODI0MTA2NzYzODYxNzY4NDUyOTYzNzYzNDQ5ODUxODc2NjMzMzQiLCIxIl0sInBpX2IiOltbIjE4MDY3ODY4NzQwMDA2MjI1NjE1NDQ3MTk0NDcxMzcwNjU4OTgwOTk5OTI2MzY5Njk1MjkzMTE1NzEyOTUxMzY2NzA3NzQ0MDY0NjA2IiwiMjE1OTkyNDE1NzA1NDc3MzEyMzQzMDQwMzk5ODkxNjY0MDY0MTU4OTk3MTc2NTkxNzE3NjAwNDM4OTk1MDkxNTIwMTE0Nzk2NjM3NTciXSxbIjY2OTk1NDA3MDUwNzQ5MjQ5OTc5NjcyNzUxODYzMjQ3NTU0NDIyNjA2MDc2NzE1MzY0MzQ0MDMwNjU1MjkxNjQ3Njk3MDI0NzczOTgiLCIxMTI1NzY0MzI5MzIwMTYyNzQ1MDI5MzE4NTE2NDI4ODQ4MjQyMDU1OTgwNjY0OTkzNzM3MTU2ODE2MDc0MjYwMTM4NjY3MTY1OTgwMCJdLFsiMSIsIjAiXV0sInBpX2MiOlsiNjIxNjQyMzUwMzI4OTQ5NjI5Mjk0NDA1MjAzMjE5MDM1MzYyNTQyMjQxMTQ4MzM4MzM3ODk3OTAyOTY2NzI0Mzc4NTMxOTIwODA5NSIsIjE0ODE2MjE4MDQ1MTU4Mzg4NzU4NTY3NjA4NjA1NTc2Mzg0OTk0MzM5NzE0MzkwMzcwMzAwOTYzNTgwNjU4Mzg2NTM0MTU4NjAzNzExIiwiMSJdLCJwcm90b2NvbCI6Imdyb3RoMTYifSwicHViX3NpZ25hbHMiOlsiNDk3Njk0Mzk0Mzk2NjM2NTA2MjEyMzIyMTk5OTgzODAxMzE3MTIyODE1NjQ5NTM2NjI3MDM3NzI2MTM4MDQ0OTc4Nzg3MTg5ODY3MiIsIjE4NjU2MTQ3NTQ2NjY2OTQ0NDg0NDUzODk5MjQxOTE2NDY5NTQ0MDkwMjU4ODEwMTkyODAzOTQ5NTIyNzk0NDkwNDkzMjcxMDA1MzEzIiwiMzc5OTQ5MTUwMTMwMjE0NzIzNDIwNTg5NjEwOTExMTYxODk1NDk1NjQ3Nzg5MDA2NjQ5Nzg1MjY0NzM4MTQxMjk5MTM1NDE0MjcyIl19`

	authInstance := Verifier{&FileKeyLoader{}, state.VerificationOptions{
		Contract: "0xa36786c3e18225da7cc8fc69c6443ecd41827ff5",
		RPCUrl:   os.Getenv("RPC_URL"),
	}}
	parsedToken, err := authInstance.VerifyJWZ(context.Background(), token)
	assert.Nil(t, err)
	assert.Equal(t, parsedToken.Alg, "groth16")
}

func TestVerifier_FullVerify(t *testing.T) {

	t.Skip()
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
	request, err := CreateAuthorizationRequestWithMessage(reason, "message to sign", verifierID, callbackURL)
	assert.Nil(t, err)
	request.Body.Scope = append(request.Body.Scope, mtpProofRequest)
	request.ID = "7f38a193-0918-4a48-9fac-36adfdb8b542"
	request.ThreadID = "7f38a193-0918-4a48-9fac-36adfdb8b542" // because it's used in the response

	token := `eyJhbGciOiJncm90aDE2IiwiY2lyY3VpdElkIjoiYXV0aCIsImNyaXQiOlsiY2lyY3VpdElkIl0sInR5cCI6ImFwcGxpY2F0aW9uL2lkZW4zLXprcC1qc29uIn0.eyJpZCI6IjI4NDk0MDA3LTljNDktNGYxYS05Njk0LTc3MDBjMDg4NjViZiIsInR5cCI6ImFwcGxpY2F0aW9uL2lkZW4zY29tbS1wbGFpbi1qc29uIiwidHlwZSI6Imh0dHBzOi8vaWRlbjMtY29tbXVuaWNhdGlvbi5pby9hdXRob3JpemF0aW9uLzEuMC9yZXNwb25zZSIsInRoaWQiOiI3ZjM4YTE5My0wOTE4LTRhNDgtOWZhYy0zNmFkZmRiOGI1NDIiLCJib2R5Ijp7Im1lc3NhZ2UiOiJtZXNzYWdlIHRvIHNpZ24iLCJzY29wZSI6W3siaWQiOjEsImNpcmN1aXRfaWQiOiJjcmVkZW50aWFsQXRvbWljUXVlcnlNVFAiLCJwcm9vZiI6eyJwaV9hIjpbIjIwOTczNDg1MTA3MTg2NjEzODM1Mjk0NDIwNTA0MTY4ODQ0OTAwMDYwNDI5NzQ1MTgwMjc3MzcwMDc4MTM2NjQ1NDIzMzIzNzk2OTg4IiwiMjA4NzY1MTIzNTU1MTc0NTQzNTgzODczNTIzNTc0MzA0NjkyNjk1MzI1MTEyMDg0Mjc3MDI0MzU2NDA5NTQyMTI0MTQ4NDY3OTQ5ODgiLCIxIl0sInBpX2IiOltbIjE1MzU5Nzg3NzkyMjkxMzAxNTI0NDI5NTExNTYzMTYzODE5ODMzMjA5NjcwNTg2ODkxNDk5MTQ5ODgwMTAzODk3ODIxNjMxODEyMzIwIiwiOTUyMTQ4MDk3NzQxMzE4NzUwNDAxNDA2Njc4MjQ4ODY0NDgyNDA4MTEzNDE4NzI4MDQ1NTQxODUzMjU0ODM4NzkwMjExOTQ0NTU3Il0sWyIzODY2NTQ3MDY4OTg4Mzc4NDE5Nzg3MjE2NDk0ODUwNDQxOTM3MzkzNzQ4ODQ5ODU5NDExNjE5OTk1MDMwMDkxNjY2Njc4MjM0MjMzIiwiMTI3MzcyNjA5NTQ5ODM3NzIwNDc2ODA0Mzc5NDExOTM2NzU4ODYyMTUzMTU0NjM5NjUwOTk1MjcyMTUzNTQ0Mjg4NTYxNjY1ODkyMjAiXSxbIjEiLCIwIl1dLCJwaV9jIjpbIjE0MDMyMDUxNjY5Mzc2NTE5OTMyOTU3MDcyMTQ3MzgyNzM5MTM0NjU4ODg1NzgyNjYxMzkwMTcwNjU4NjMxMTA3Nzk1Mzg2MDM0OTkwIiwiMzQyNjY1MTkyMDE2ODU3NjE0MTMyODQ2NjQ0MTM4NTg3Mjg5NDgyNDQxNzE0MTc4ODI2MDgzMDgzMjU2MzcwNzk1MDYwNTAzNDU0MiIsIjEiXSwicHJvdG9jb2wiOiJncm90aDE2In0sInB1Yl9zaWduYWxzIjpbIjIyNzk5OTc5MjU2MDYwMTU4MTE0MzkyMzEyMTIxMDM4ODM4MjE5ODI3NjgyODkzMjExMjIzNzc0MjMxOTE1MzcwOTI3NDIzNDg4MCIsIjEwMDk5Nzg5NjY1MzAwOTc1NDU3ODAyMTc4ODYyMjk2MDk4MjcxMjQzMzU5NjYwMzE1ODAyNzU5NDk1MDE2Mjg1MzUyNjQwMjEyODE0IiwiMTIzNDUiLCI4MzkwNzk1NjU0NzM5MjAzOTcyNjE2OTI2Nzc0MDkxNDQ1NDk4NDUxNTIwODEzMTQyMTIxMzY1Njc4NTY1MTM2MjI4NTI4NzI1MzEyIiwiMjA2ODExNzkxNDMxMjY5NzA3NDI3NTg5MzAyMjc0OTUyNDczMTQ3ODc5ODg4MDIyMTQyMDk2MzYzOTUwNDY1NjU2MDE0MTEwNzIwIiwiMTY1MzA1NzA2MiIsIjEwNjU5MDg4MDA3MzMwMzQxODgxODQ5MDcxMDYzOTU1NjcwNDQ2MiIsIjIiLCI0IiwiODQwIiwiMTIwIiwiMzQwIiwiNTA5IiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIl19XX0sImZyb20iOiIxMTl0cWNlV2RSZDJGNlduQXlWdUZRUkZqSzNXVVhxMkxvclNQeUc5TEoiLCJ0byI6IjExMjVHSnFndzZZRXNLRndqNjNHWTg3TU14UEw5a3dES3hQVWl3TUxOWiJ9.eyJwcm9vZiI6eyJwaV9hIjpbIjEwNDEyNDM2MTk3NDk0NDc5NTg3Mzk2NjY3Mzg1NzA3MzY4MjgyNTY4MDU1MTE4MjY5ODY0NDU3OTI3NDc2OTkwNjM2NDE5NzAyNDUxIiwiMTA3ODE3MzkwOTU0NDUyMDE5OTY0Njc0MTQ4MTc5NDE4MDU4Nzk5ODI0MTA2NzYzODYxNzY4NDUyOTYzNzYzNDQ5ODUxODc2NjMzMzQiLCIxIl0sInBpX2IiOltbIjE4MDY3ODY4NzQwMDA2MjI1NjE1NDQ3MTk0NDcxMzcwNjU4OTgwOTk5OTI2MzY5Njk1MjkzMTE1NzEyOTUxMzY2NzA3NzQ0MDY0NjA2IiwiMjE1OTkyNDE1NzA1NDc3MzEyMzQzMDQwMzk5ODkxNjY0MDY0MTU4OTk3MTc2NTkxNzE3NjAwNDM4OTk1MDkxNTIwMTE0Nzk2NjM3NTciXSxbIjY2OTk1NDA3MDUwNzQ5MjQ5OTc5NjcyNzUxODYzMjQ3NTU0NDIyNjA2MDc2NzE1MzY0MzQ0MDMwNjU1MjkxNjQ3Njk3MDI0NzczOTgiLCIxMTI1NzY0MzI5MzIwMTYyNzQ1MDI5MzE4NTE2NDI4ODQ4MjQyMDU1OTgwNjY0OTkzNzM3MTU2ODE2MDc0MjYwMTM4NjY3MTY1OTgwMCJdLFsiMSIsIjAiXV0sInBpX2MiOlsiNjIxNjQyMzUwMzI4OTQ5NjI5Mjk0NDA1MjAzMjE5MDM1MzYyNTQyMjQxMTQ4MzM4MzM3ODk3OTAyOTY2NzI0Mzc4NTMxOTIwODA5NSIsIjE0ODE2MjE4MDQ1MTU4Mzg4NzU4NTY3NjA4NjA1NTc2Mzg0OTk0MzM5NzE0MzkwMzcwMzAwOTYzNTgwNjU4Mzg2NTM0MTU4NjAzNzExIiwiMSJdLCJwcm90b2NvbCI6Imdyb3RoMTYifSwicHViX3NpZ25hbHMiOlsiNDk3Njk0Mzk0Mzk2NjM2NTA2MjEyMzIyMTk5OTgzODAxMzE3MTIyODE1NjQ5NTM2NjI3MDM3NzI2MTM4MDQ0OTc4Nzg3MTg5ODY3MiIsIjE4NjU2MTQ3NTQ2NjY2OTQ0NDg0NDUzODk5MjQxOTE2NDY5NTQ0MDkwMjU4ODEwMTkyODAzOTQ5NTIyNzk0NDkwNDkzMjcxMDA1MzEzIiwiMzc5OTQ5MTUwMTMwMjE0NzIzNDIwNTg5NjEwOTExMTYxODk1NDk1NjQ3Nzg5MDA2NjQ5Nzg1MjY0NzM4MTQxMjk5MTM1NDE0MjcyIl19`

	authInstance := Verifier{&FileKeyLoader{}, state.VerificationOptions{
		Contract: "0xa36786c3e18225da7cc8fc69c6443ecd41827ff5",
		RPCUrl:   os.Getenv("RPC_URL"),
	}}
	err = authInstance.FullVerify(context.Background(), token, *request)
	assert.Nil(t, err)
}
