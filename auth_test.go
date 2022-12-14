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
var stateResolver = &mockStateResolver{}

type mockStateResolver struct {
}

func (r *mockStateResolver) Resolve(_ context.Context, id, s *big.Int) (*state.ResolvedState, error) {
	return &state.ResolvedState{Latest: true, Genesis: false, TransitionTimestamp: 0}, nil
}

func (r *mockStateResolver) ResolveGlobalRoot(_ context.Context, _ *big.Int) (*state.ResolvedState, error) {
	return &state.ResolvedState{Latest: true, TransitionTimestamp: 0}, nil
}

func TestVerifyMessageWithMTPProof_V2(t *testing.T) {
	verifierID := "1125GJqgw6YEsKFwj63GY87MMxPL9kwDKxPUiwMToR"
	callbackURL := "https://test.com/callback"
	reason := "test"

	var mtpProofRequest protocol.ZeroKnowledgeProofRequest
	mtpProofRequest.ID = 10
	mtpProofRequest.CircuitID = string(circuits.AtomicQueryMTPV2CircuitID)
	opt := true
	mtpProofRequest.Optional = &opt
	mtpProofRequest.Query = map[string]interface{}{
		"query": pubsignals.Query{
			AllowedIssuers: "*",
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
			Context: "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
			Type:    "KYCCountryOfResidenceCredential",
		},
	}
	request := CreateAuthorizationV2RequestWithMessage(reason, "message to sign", verifierID, callbackURL)
	request.Body.Scope = append(request.Body.Scope, mtpProofRequest)

	userID := "did:iden3:polygon:mumbai:x3vgBmSWMecbkxFAvT8waWejmCLmzHcrG56sXbAhB"
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
							"553107328829552739356143409585452140182890751904479913169932084064672719342",
							"6414164353444149373251860755937247195440148247977996873464801175864488600187",
							"1",
						},
						B: [][]string{
							{
								"1848793935234157552257829088144777701654345181741201635414140644827541802063",
								"2690669073070388025072668654408175248782610232957303774118462170802712453278",
							},
							{
								"5055095222783166923422204514647227537440069458420869376587492848653363173060",
								"483202060159956789222074171559922542038004267623840366839963428406782614282",
							},
							{
								"1",
								"0",
							}},
						C: []string{
							"1629496919538541173933472398151128146708748529834203088117936150271440668414",
							"14513257679897863036989550655794291459834670206310872236326790971807658823114",
							"1",
						},
						Protocol: "groth16",
					},
					PubSignals: []string{
						"1",
						"26337405203610566029241995866156151469433315212067050574696144339180786177",
						"10",
						"26337405203610566029241995866156151469433315212067050574696144339180786177",
						"21498905153686139720023221743570456290445230580677931307974644282469683226010",
						"21498905153686139720023221743570456290445230580677931307974644282469683226010",
						"1670860707",
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

	authInstance := Verifier{verificationKeyloader, schemaLoader, stateResolver}
	err := authInstance.VerifyAuthResponse(context.Background(), message, request)
	require.Nil(t, err)
}

func TestVerifier_VerifyJWZ_V2(t *testing.T) {

	token := ` eyJhbGciOiJncm90aDE2IiwiY2lyY3VpdElkIjoiYXV0aFYyIiwiY3JpdCI6WyJjaXJjdWl0SWQiXSwidHlwIjoiSldaIn0.bXltZXNzYWdl.eyJwcm9vZiI6eyJwaV9hIjpbIjE4MTE5Mjg3MTg1OTMzNjAxOTkzMTM5NTg1MzI3NjU5Mjc0ODQ1OTMzNjg5MzQ2NTU1MTkyODY0MDM0Mjg5MzAwMjA4MDk3MTIyODkwIiwiNjIyOTUwNjkyNzcwMzg5MjI1NjA1ODU1MjMxOTE4ODA0ODE0ODYwODEwMzg4ODU2MjE5ODM3Mjk2MzIxMzY1OTM4NTQxOTU3MDA3NiIsIjEiXSwicGlfYiI6W1siMjcyNTMzNjczNTQwODEwNTgxMjg2ODc1MjgyMzQ4NDE3NzA3OTkxMzM4MjAwNzMyNTg2NjU2MjE1NjE1OTU3MjI0MjgwMTE0MjgyOSIsIjQzNjA1NTYyNjkxMjIzNTM0ODY2MjQ1NjkyMjY0MDQ5ODMxNDI1NTYyMzk5ODA3OTAxNjkwMjkwMzI3MTUxMzE3ODUzMjA2ODc0MjYiXSxbIjE4NjEzMDEyMjk1MTc1NDY3NjQyMzMxMDkzNDkyODY4MjQ4NzYxNzQzMzk1Mjg3NzI0MzMxMTQ3OTA0NzE4NTY2MDEzMTI2NDMyNTMxIiwiMTkzNzA0NzU2MDcyMzIxNjAwOTQ2NjY3ODYxODEzODgxNzU5NTQyMjQ1ODYyMDAxNjUzMzUyNDU3NDkxNjM5NjEzMjk5NzM1NzkzMjIiXSxbIjEiLCIwIl1dLCJwaV9jIjpbIjE0MzQyNDIxMTE5MzA4MDQzMTM1OTk2NDE5NjYyMzAxMTEwMzU2MTQ5OTc1NDg1NDI0MDUyMjI1MDY0NTU4NTQ1MDg4NTc2NjY4NDU3IiwiMjE1MzU5NzU0NTU0MjU3MzUzNjI5MDY3NjA5NzU2MjkxMTEyMDk4NDgyNzQzNDI2NjU3MTQ4OTYyMjQ2OTE4NzAxNjA3MDM2NTQxOTUiLCIxIl0sInByb3RvY29sIjoiZ3JvdGgxNiJ9LCJwdWJfc2lnbmFscyI6WyIxOTIyOTA4NDg3MzcwNDU1MDM1NzIzMjg4NzE0Mjc3NDYwNTQ0MjI5NzMzNzIyOTE3NjU3OTIyOTAxMTM0MjA5MTU5NDE3NDk3NyIsIjYxMTA1MTc3NjgyNDk1NTkyMzgxOTM0Nzc0MzU0NTQ3OTIwMjQ3MzIxNzM4NjU0ODg5MDAyNzA4NDk2MjQzMjg2NTA3NjU2OTE0OTQiLCIxMjQzOTA0NzExNDI5OTYxODU4Nzc0MjIwNjQ3NjEwNzI0MjczNzk4OTE4NDU3OTkxNDg2MDMxNTY3MjQ0MTAwNzY3MjU5MjM5NzQ3Il19 `

	authInstance := Verifier{verificationKeyloader, schemaLoader, stateResolver}
	parsedToken, err := authInstance.VerifyJWZ(context.Background(), token)
	assert.NoError(t, err)
	assert.Equal(t, parsedToken.Alg, "groth16")
}

func TestVerifier_FullVerify_V2(t *testing.T) {
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
		"query": pubsignals.Query{
			AllowedIssuers: "*",
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
			Context: "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
			Type:    "KYCCountryOfResidenceCredential",
		},
	}
	request := CreateAuthorizationV2RequestWithMessage(reason, "message to sign", verifierID, callbackURL)
	request.Body.Scope = append(request.Body.Scope, mtpProofRequest)
	request.ID = "28494007-9c49-4f1a-9694-7700c08865bf"
	request.ThreadID = "ee92ab12-2671-457e-aa5e-8158c205a985" // because it's used in the response

	token := ` eyJhbGciOiJncm90aDE2IiwiY2lyY3VpdElkIjoiYXV0aFYyIiwiY3JpdCI6WyJjaXJjdWl0SWQiXSwidHlwIjoiSldaIn0.eyJpZCI6IjIzMjVhNTMzLTZhYjMtNGVkZi05YmZhLTI3OGEyOWQzMWI2YiIsInR5cCI6ImFwcGxpY2F0aW9uL2lkZW4zY29tbS1wbGFpbi1qc29uIiwidHlwZSI6Imh0dHBzOi8vaWRlbjMtY29tbXVuaWNhdGlvbi5pby9hdXRob3JpemF0aW9uLzEuMC9yZXNwb25zZSIsInRoaWQiOiJmODNjYzFlZC1kODU1LTRmNTEtYjBiMy00Y2Q5ODFiNmI0ZTgiLCJib2R5Ijp7Im1lc3NhZ2UiOiJtZXNzYWdlIHRvIHNpZ24iLCJzY29wZSI6W3siaWQiOjEwLCJjaXJjdWl0SWQiOiJjcmVkZW50aWFsQXRvbWljUXVlcnlNVFBWMiIsInByb29mIjp7InBpX2EiOlsiNTUzMTA3MzI4ODI5NTUyNzM5MzU2MTQzNDA5NTg1NDUyMTQwMTgyODkwNzUxOTA0NDc5OTEzMTY5OTMyMDg0MDY0NjcyNzE5MzQyIiwiNjQxNDE2NDM1MzQ0NDE0OTM3MzI1MTg2MDc1NTkzNzI0NzE5NTQ0MDE0ODI0Nzk3Nzk5Njg3MzQ2NDgwMTE3NTg2NDQ4ODYwMDE4NyIsIjEiXSwicGlfYiI6W1siMTg0ODc5MzkzNTIzNDE1NzU1MjI1NzgyOTA4ODE0NDc3NzcwMTY1NDM0NTE4MTc0MTIwMTYzNTQxNDE0MDY0NDgyNzU0MTgwMjA2MyIsIjI2OTA2NjkwNzMwNzAzODgwMjUwNzI2Njg2NTQ0MDgxNzUyNDg3ODI2MTAyMzI5NTczMDM3NzQxMTg0NjIxNzA4MDI3MTI0NTMyNzgiXSxbIjUwNTUwOTUyMjI3ODMxNjY5MjM0MjIyMDQ1MTQ2NDcyMjc1Mzc0NDAwNjk0NTg0MjA4NjkzNzY1ODc0OTI4NDg2NTMzNjMxNzMwNjAiLCI0ODMyMDIwNjAxNTk5NTY3ODkyMjIwNzQxNzE1NTk5MjI1NDIwMzgwMDQyNjc2MjM4NDAzNjY4Mzk5NjM0Mjg0MDY3ODI2MTQyODIiXSxbIjEiLCIwIl1dLCJwaV9jIjpbIjE2Mjk0OTY5MTk1Mzg1NDExNzM5MzM0NzIzOTgxNTExMjgxNDY3MDg3NDg1Mjk4MzQyMDMwODgxMTc5MzYxNTAyNzE0NDA2Njg0MTQiLCIxNDUxMzI1NzY3OTg5Nzg2MzAzNjk4OTU1MDY1NTc5NDI5MTQ1OTgzNDY3MDIwNjMxMDg3MjIzNjMyNjc5MDk3MTgwNzY1ODgyMzExNCIsIjEiXSwicHJvdG9jb2wiOiJncm90aDE2In0sInB1Yl9zaWduYWxzIjpbIjEiLCIyNjMzNzQwNTIwMzYxMDU2NjAyOTI0MTk5NTg2NjE1NjE1MTQ2OTQzMzMxNTIxMjA2NzA1MDU3NDY5NjE0NDMzOTE4MDc4NjE3NyIsIjEwIiwiMjYzMzc0MDUyMDM2MTA1NjYwMjkyNDE5OTU4NjYxNTYxNTE0Njk0MzMzMTUyMTIwNjcwNTA1NzQ2OTYxNDQzMzkxODA3ODYxNzciLCIyMTQ5ODkwNTE1MzY4NjEzOTcyMDAyMzIyMTc0MzU3MDQ1NjI5MDQ0NTIzMDU4MDY3NzkzMTMwNzk3NDY0NDI4MjQ2OTY4MzIyNjAxMCIsIjIxNDk4OTA1MTUzNjg2MTM5NzIwMDIzMjIxNzQzNTcwNDU2MjkwNDQ1MjMwNTgwNjc3OTMxMzA3OTc0NjQ0MjgyNDY5NjgzMjI2MDEwIiwiMTY3MDg2MDcwNyIsIjMzNjYxNTQyMzkwMDkxOTQ2NDE5MzA3NTU5Mjg1MDQ4MzcwNDYwMCIsIjAiLCIxNzAwMjQzNzExOTQzNDYxODc4MzU0NTY5NDYzMzAzODUzNzM4MDcyNjMzOTk5NDI0NDY4NDM0ODkxMzg0NDkyMzQyMjQ3MDgwNjg0NCIsIjAiLCI1IiwiODQwIiwiMTIwIiwiMzQwIiwiNTA5IiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIl19XX0sImZyb20iOiJkaWQ6aWRlbjM6cG9seWdvbjptdW1iYWk6eDN2Z0JtU1dNZWNia3hGQXZUOHdhV2VqbUNMbXpIY3JHNTZzWGJBaEIiLCJ0byI6IjExMjVHSnFndzZZRXNLRndqNjNHWTg3TU14UEw5a3dES3hQVWl3TVRvUiJ9.eyJwcm9vZiI6eyJwaV9hIjpbIjExODQwMzkxMjMwNzg1NDA3MDY2ODkyMDc3MDc1NTQ2NTA2MzIzMDUyNzk2MTUxMDExNzMyMDQ1ODE3MTQxMDg3NDE5OTQ2MzE1ODUyIiwiMjE4MzM2MTY0NTYzNTg5NzU5OTM0NzAyODMxMzY4MDc1MzYzNjY1MzA5NzA4OTU5ODQ1NDU5MDYyNzgxNzQ3NjMyOTU5MzU1ODE2MjIiLCIxIl0sInBpX2IiOltbIjIxMTUzOTg0MDc3NzIxNDUzNjA4NDE4NTg2MDYyMzc5MzQ3MDEzNTU3MTMzNjMzNjQxOTg4NTIzODI4MjYyNTgwMTgyNTQzNzc0OTgzIiwiMjcwNDIxNDUxNjI4MzcxNTcyMjUzMzI0NDc2MjQzOTk4MjIxNzczMTY4MDAxNjExNzAyMjk0Nzk1MzM3NzU4MzI1MDQ0MjEwMDI2MSJdLFsiMjA1MTEzNDkzNDA3MTEwNTc1NjE5MTExNjk3NjM1MTE5NTA2MzA4NzMzMjc3ODExMTk3OTgwNDQyMTU4NzQ5OTQ2NzA1NzMxNDc3NzEiLCIxOTgxNzc1MTEwNTQzNjAzODU3MDcyOTg0MjAwNjgwOTM0OTExNTQ0MzMxNDc5NjUwNzU5NjkzODc2NjY5NTM3NjE4ODI0NTMwNjMwNSJdLFsiMSIsIjAiXV0sInBpX2MiOlsiMjc2NzE2NTA5OTY0MjgxOTk4OTI2NzI4MTYyOTc0MTYwMjcxNDI1NzA4ODMwNTU3MDYyOTExMjY1MTA3Nzc4MjE3Mzg4NDExMDkxOSIsIjY2NTc2ODM5MjMzNzg1MTkwODQxMDYxMTkyMjQ0NTgzNTk3NjUyMzUyOTA1MjY1OTcxMTIzMTk3OTg5NDU2Nzg0NDA0NTMxNzA4MzkiLCIxIl0sInByb3RvY29sIjoiZ3JvdGgxNiJ9LCJwdWJfc2lnbmFscyI6WyIyNjMzNzQwNTIwMzYxMDU2NjAyOTI0MTk5NTg2NjE1NjE1MTQ2OTQzMzMxNTIxMjA2NzA1MDU3NDY5NjE0NDMzOTE4MDc4NjE3NyIsIjM1MzUwMTI4MzMxOTE5MTcyNDM2MDQyODAyODU1ODkxNzcyNTkwNjI0MTQ0NjMzMjA2NDk0MTM1NDE5ODE5MzQyMDI3MDc1NDIyMjEiLCIxMzU3ODkzODY3NDI5OTEzODA3MjQ3MTQ2MzY5NDA1NTIyNDgzMDg5MjcyNjIzNDA0ODUzMjUyMDMxNjM4NzcwNDg3ODAwMDAwODc5NSJdfQ`

	authInstance := Verifier{verificationKeyloader, schemaLoader, stateResolver}
	_, err := authInstance.FullVerify(context.Background(), token, request)
	assert.Nil(t, err)

}

func TestVerifyAuthResponseWithEmptyReq(t *testing.T) {

	verifierID := "1125GJqgw6YEsKFwj63GY87MMxPL9kwDKxPUiwMLNZ"
	callbackURL := "https://test.com/callback"
	reason := "test"

	userID := "did:iden3:polygon:mumbai:x3vgBmSWMecbkxFAvT8waWejmCLmzHcrG56sXbAhB"
	var zkReq protocol.ZeroKnowledgeProofRequest
	zkReq.ID = 10
	zkReq.CircuitID = string(circuits.AtomicQueryMTPV2CircuitID)
	opt := true
	zkReq.Optional = &opt
	zkReq.Query = map[string]interface{}{
		"query": pubsignals.Query{
			AllowedIssuers: "*",
			Context:        "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
			Type:           "KYCCountryOfResidenceCredential",
		},
	}

	authReq := CreateAuthorizationV2RequestWithMessage(reason, "test", verifierID, callbackURL)
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
								"553107328829552739356143409585452140182890751904479913169932084064672719342",
								"6414164353444149373251860755937247195440148247977996873464801175864488600187",
								"1",
							},
							B: [][]string{
								{
									"1848793935234157552257829088144777701654345181741201635414140644827541802063",
									"2690669073070388025072668654408175248782610232957303774118462170802712453278",
								},
								{
									"5055095222783166923422204514647227537440069458420869376587492848653363173060",
									"483202060159956789222074171559922542038004267623840366839963428406782614282",
								},
								{
									"1",
									"0",
								}},
							C: []string{
								"1629496919538541173933472398151128146708748529834203088117936150271440668414",
								"14513257679897863036989550655794291459834670206310872236326790971807658823114",
								"1",
							},
							Protocol: "groth16",
						},
						PubSignals: []string{
							"1",
							"26337405203610566029241995866156151469433315212067050574696144339180786177",
							"10",
							"26337405203610566029241995866156151469433315212067050574696144339180786177",
							"21498905153686139720023221743570456290445230580677931307974644282469683226010",
							"21498905153686139720023221743570456290445230580677931307974644282469683226010",
							"1670860707",
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

	authInstance := Verifier{verificationKeyloader, schemaLoader, stateResolver}
	err := authInstance.VerifyAuthResponse(context.Background(), resp, authReq)
	assert.NoError(t, err)
}

func TestCreateAuthorizationV2Request(t *testing.T) {

	sender := "1125GJqgw6YEsKFwj63GY87MMxPL9kwDKxPUiwMLNZ"
	callbackURL := "https://test.com/callback"
	reason := "basic authentication"

	request := CreateAuthorizationV2Request(reason, sender, callbackURL)
	assert.Len(t, request.Body.Scope, 0)
	assert.Equal(t, callbackURL, request.Body.CallbackURL)
	assert.Equal(t, sender, request.From)
	assert.Equal(t, protocol.AuthorizationV2RequestMessageType, request.Type)

}

func TestCreateAuthorizationV2RequestWithMessage(t *testing.T) {

	sender := "1125GJqgw6YEsKFwj63GY87MMxPL9kwDKxPUiwMLNZ"
	callbackURL := "https://test.com/callback"
	reason := "basic authentication"
	message := "message"

	request := CreateAuthorizationV2RequestWithMessage(reason, message, sender, callbackURL)
	assert.Len(t, request.Body.Scope, 0)
	assert.Equal(t, callbackURL, request.Body.CallbackURL)
	assert.Equal(t, sender, request.From)
	assert.Equal(t, protocol.AuthorizationV2RequestMessageType, request.Type)
	assert.Equal(t, message, request.Body.Message)
}
