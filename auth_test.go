package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/iden3/go-circuits/v2"
	"github.com/iden3/go-iden3-auth/v2/loaders"
	"github.com/iden3/go-iden3-auth/v2/pubsignals"
	"github.com/iden3/go-iden3-auth/v2/state"
	"github.com/iden3/go-rapidsnark/types"
	"github.com/iden3/go-schema-processor/v2/verifiable"
	"github.com/iden3/iden3comm/v2/packers"
	"github.com/iden3/iden3comm/v2/protocol"
	"github.com/piprate/json-gold/ld"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	// we have multiimport since two different libraries use the same package
	// with different versions
	// Same issue https://github.com/flashbots/mev-boost-relay/pull/227/files
	_ "github.com/btcsuite/btcd/btcutil"
)

var verificationKeyloader = &loaders.FSKeyLoader{Dir: "./testdata"}

type mockJSONLDSchemaLoader struct {
	schemas map[string]string
	seen    map[string]bool
}

func (r *mockJSONLDSchemaLoader) LoadDocument(u string) (*ld.RemoteDocument, error) {
	if body, ok := r.schemas[u]; ok {
		if r.seen == nil {
			r.seen = make(map[string]bool)
		}
		r.seen[u] = true
		var doc = ld.RemoteDocument{DocumentURL: u}
		err := json.Unmarshal([]byte(body), &doc.Document)
		return &doc, err
	}
	return nil, fmt.Errorf("schema not found: %v", u)
}

// assert that all schemas were loaded
func (r *mockJSONLDSchemaLoader) assert(t testing.TB) {
	for url := range r.schemas {
		require.True(t, r.seen[url], "schema not loaded: %v", url)
	}
}

/*
mock for state resolver
*/
var stateResolvers = map[string]pubsignals.StateResolver{
	"polygon:mumbai": &mockStateResolver{},
}

const proofGenerationDelay = time.Hour * 100000

type mockStateResolver struct {
}

func (r *mockStateResolver) Resolve(_ context.Context, _, _ *big.Int) (*state.ResolvedState, error) {
	return &state.ResolvedState{Latest: true, Genesis: false, TransitionTimestamp: 0}, nil
}

func (r *mockStateResolver) ResolveGlobalRoot(_ context.Context, _ *big.Int) (*state.ResolvedState, error) {
	return &state.ResolvedState{Latest: true, TransitionTimestamp: 0}, nil
}

func TestVerifyMessageWithSigProof_NonMerkalized(t *testing.T) {
	verifierID := "did:polygonid:polygon:mumbai:2qEevY9VnKdNsVDdXRv3qSLHRqoMGMRRdE5Gmc6iA7"
	callbackURL := "https://test.com/callback"
	reason := "test"

	var mtpProofRequest protocol.ZeroKnowledgeProofRequest
	mtpProofRequest.ID = 84239
	mtpProofRequest.CircuitID = string(circuits.AtomicQuerySigV2CircuitID)
	opt := true
	mtpProofRequest.Optional = &opt
	mtpProofRequest.Query = map[string]interface{}{
		"allowedIssuers": []string{"*"},
		"credentialSubject": map[string]interface{}{
			"documentType": map[string]interface{}{
				"$eq": 99,
			},
		},
		"context": "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-nonmerklized.jsonld",
		"type":    "KYCAgeCredential",
	}
	request := CreateAuthorizationRequestWithMessage(reason, "message to sign", verifierID, callbackURL)
	request.Body.Scope = append(request.Body.Scope, mtpProofRequest)

	userID := "did:polygonid:polygon:mumbai:2qESoaGFEnva4pPwsrAFBQVGDe9nWZjxnYPx9iZCmy"
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
				ID:        84239,
				CircuitID: mtpProofRequest.CircuitID,
				ZKProof: types.ZKProof{
					Proof: &types.ProofData{
						A: []string{
							"2611057193079519143943574762976163751513297830204274538165209742319404560009",
							"12788136479543687707691255840000266348710592817282837814793759907273190108832",
							"1",
						},
						B: [][]string{
							{
								"10339668293932770774721966230711117475856552910519491964127539856759509764538",
								"17964019159250915555109750373550416110000486687819674734837267280880888810242",
							},
							{
								"6499462520390702655745417048723495028623947635734919685001024458271017372928",
								"4784939073830356747664613674202589008960041219476254033188324784531745896723",
							},
							{
								"1",
								"0",
							}},
						C: []string{
							"2984436813221912132373797933359320407850882135995712713500068095842517260060",
							"14165028891749861878969723019325288416949269447664143825335627519902321505165",
							"1",
						},
						Protocol: "groth16",
					},
					PubSignals: []string{
						"0",
						"21644443298494844652823233093669102266165833451013044961990306925134942722",
						"17537800766613709234797664178634662536948999910610642067578271567408034578838",
						"84239",
						"21348146785008049378057709592345376828473866675540022564894550180914532866",
						"1",
						"17537800766613709234797664178634662536948999910610642067578271567408034578838",
						"1694787248",
						"198285726510688200335207273836123338699",
						"1",
						"0",
						"3",
						"1",
						"99",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
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

	schemaLoader := &mockJSONLDSchemaLoader{
		schemas: map[string]string{
			"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-nonmerklized.jsonld": loadSchema("kyc-nonmerklized.jsonld"),
		},
	}
	authInstance, err := NewVerifier(verificationKeyloader, stateResolvers,
		WithDocumentLoader(schemaLoader))
	require.NoError(t, err)
	err = authInstance.VerifyAuthResponse(context.Background(), message, request,
		pubsignals.WithAcceptedProofGenerationDelay(proofGenerationDelay))
	require.Nil(t, err)
	schemaLoader.assert(t)
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

	schemaLoader := &mockJSONLDSchemaLoader{
		schemas: map[string]string{"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld": loadSchema("kyc-v3.json-ld")},
	}
	authInstance, err := NewVerifier(verificationKeyloader, stateResolvers,
		WithDocumentLoader(schemaLoader))
	require.NoError(t, err)
	err = authInstance.VerifyAuthResponse(context.Background(), message, request, pubsignals.WithAcceptedProofGenerationDelay(proofGenerationDelay))
	require.NoError(t, err)
	schemaLoader.assert(t)
}

func TestVerifier_VerifyJWZ(t *testing.T) {

	token := `eyJhbGciOiJncm90aDE2IiwiY2lyY3VpdElkIjoiYXV0aFYyIiwiY3JpdCI6WyJjaXJjdWl0SWQiXSwidHlwIjoiYXBwbGljYXRpb24vaWRlbjMtemtwLWpzb24ifQ.eyJpZCI6IjljMGY5NjIzLWM1NmMtNDEwNC04ODk2LWVjMjgyYTNiMmExNyIsInR5cCI6ImFwcGxpY2F0aW9uL2lkZW4zY29tbS1wbGFpbi1qc29uIiwidHlwZSI6Imh0dHBzOi8vaWRlbjMtY29tbXVuaWNhdGlvbi5pby9hdXRob3JpemF0aW9uLzEuMC9yZXNwb25zZSIsInRoaWQiOiI3ZjM4YTE5My0wOTE4LTRhNDgtOWZhYy0zNmFkZmRiOGI1NDIiLCJmcm9tIjoiZGlkOnBvbHlnb25pZDpwb2x5Z29uOm11bWJhaToycVBETFhEYVUxeGExRVJUYjFYS0JmUENCM28yd0E0NnE0OW5laVhXd1kiLCJ0byI6ImRpZDpwb2x5Z29uaWQ6cG9seWdvbjptdW1iYWk6MnFKNjg5a3BvSnhjU3pCNXNBRkp0UHNTQlNySEY1ZHE3MjJCSE1xVVJMIiwiYm9keSI6eyJkaWRfZG9jIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy9ucy9kaWQvdjEiXSwiaWQiOiJkaWQ6cG9seWdvbmlkOnBvbHlnb246bXVtYmFpOjJxUERMWERhVTF4YTFFUlRiMVhLQmZQQ0IzbzJ3QTQ2cTQ5bmVpWFd3WSIsInNlcnZpY2UiOlt7ImlkIjoiZGlkOnBvbHlnb25pZDpwb2x5Z29uOm11bWJhaToycVBETFhEYVUxeGExRVJUYjFYS0JmUENCM28yd0E0NnE0OW5laVhXd1kjcHVzaCIsInR5cGUiOiJwdXNoLW5vdGlmaWNhdGlvbiIsInNlcnZpY2VFbmRwb2ludCI6Imh0dHBzOi8vcHVzaC1zdGFnaW5nLnBvbHlnb25pZC5jb20vYXBpL3YxIiwibWV0YWRhdGEiOnsiZGV2aWNlcyI6W3siY2lwaGVydGV4dCI6InhZK3RHWHUrOWlHMHZ6dFpMTTlKN25PcDNRbE1Uci85TmI3Qjl5Q0prbDlxcUpiZ1AvMExOL1VmTkxxQUk4RWZIcFhJVlVlTmVVUmNCNm82bWVMVlpJK2VvMlhvcDM2SE1iK2JyQnJTTjRqVHZWVkRDQXVXSkI2akV5Q3ZNRzlMaXp6blBsS3VQSE15dEdCVnZnV0laRFZBeVdZbTFyMk9PUzc4OU5DZm41MnNjV0VRVW5VRWdnTmpyWjlLdFpmb09RMlBDbUpqRXpDejg0ZUc3RGM2bEFvbi8ycTJJNVlLQk12RkhnT3c4N25wb0owczVrQ1RVVENjeVRlQmg2VXpLQk5aNElibndvR3ZYcG9FelBVZXZRdjRGbXVTaExYYVF3Vk9nalRBUXR0T2g2SjZhcmE4UHNndVFGQ3dNUTlxV2JjTjZYdXlScjk4TVlqbGxpL0VEN09TZzBsWVU5cUdLa1RaL2ZZN2VWZkYyeFFhOWZXK01WVzlxM2NJMjJzbkRwV28xY1ZYNWt1TWhpbmFsajZXV1Q0OTAvblNXak1rZ3JkL25CdXNiMHR4eG1jWDU3QUowcVlyMkNsK0pQb1FhcExiOEFTT3dGYU5kRDRZV3pKWXRXVmlDbktMZ3dQNDFHaGl5NVNWZE1vbU1sUy9kSGo2TVZPMjNyOVRiTDFrRy8rdkFIZWF0YkdvZ3p1OWd3SzlJckF3WS95THhMYVpQcHZzdlJLWjVBa2E1b1pkbmRNNkdLUkM0OVhoVXloQnNlY0N2Z1hNeGZGNVBnWGhROVFTb1drMzFXSWRiWG5vbmU2YmVNQkpLUVYzemg2MmpoZUFuV3czZW16dndKajRUUHU4WTJQZ2lDL3FaZXhlUVlKdFNkelJXZUFjK2N5a2ZwTXA0SmdrV2hBPSIsImFsZyI6IlJTQS1PQUVQLTUxMiJ9XX19XX0sIm1lc3NhZ2UiOm51bGwsInNjb3BlIjpbeyJpZCI6MjMsImNpcmN1aXRJZCI6ImNyZWRlbnRpYWxBdG9taWNRdWVyeU1UUFYyIiwicHJvb2YiOnsicGlfYSI6WyIyNjEwNjg1Nzc1MTY0Mzc0MDE2MTM5NDQwNTM4NzMxODI0NTgzNjQyODg0MTQxMzA5MTQwNDgzNDU0ODMzNzcyMjYxNDQ2NTI2NTEiLCIxNDE5MTI2MDA3MTY5NTk4MDAxMTY3OTUwMTgwODQ1MzIyMjI2NzUyMDcyMTc2Nzc1Nzc1OTE1MDEwMTk3NDM4MjA1MzE2MTY3NDYxMSIsIjEiXSwicGlfYiI6W1siNzY3MDg0Nzg0NDAxNTExNjk1NzUyNjE4MzcyODE5Njk3Nzk1NzMxMjYyNzMwNzc5NzkxOTU1NDEzNDY4NDkwMTQwMTQzNjAyMTk3NyIsIjE0OTU3ODQ1NDcyNjMwMDE3MDk1ODIxODMzMjIyNTgwMTk0MDYxMjY2MTg2ODUxNjM0MDUzODk3NzY4NzM4MjUzNjYzMjUzNjUwODM1Il0sWyIxNzgzNTY0MjQ1ODQ4NDYyODYyNzU1NjMyOTg3NjkxOTA3NzMzMzkxMjAxMTIzNTMwODc1ODgzMjE3Mjg4MDAxMjgxMzM5NzAyMjEwNCIsIjE4MTAwODYxMTMwMTQ5Njc4MTUzMTMzMDI1MDMxNzA5ODk3MTIwMDk3MDk4NTkxMjk4ODE3MzY3NDkxOTIwNTUzMDM3MDExNjUwMjI4Il0sWyIxIiwiMCJdXSwicGlfYyI6WyI2MjE3ODY1OTQ5Mjk5OTkwNjQyODMyNTIzMjU2ODYzMDQ4OTMyMjEwNTQ2MDQ5MjAzMTg5MTEzMzYyODUxNDc2OTY2ODI0MTYyMTkxIiwiMTkwMTY5NDkyMjUyNzc3NTU2OTAwMTk2NDczODU4NTU5MzY5Njk5Mjg5OTQyMTA5MDU5OTI2MjgzMDE5Njc4ODM4MDM2NzA0MzY1MTAiLCIxIl0sInByb3RvY29sIjoiZ3JvdGgxNiIsImN1cnZlIjoiYm4xMjgifSwicHViX3NpZ25hbHMiOlsiMSIsIjI3MTUyNjc2OTg3MTI4NTQyMDY2ODA4NTkxOTk4NTczMDAwMzcwNDM2NDY0NzIyNTE5NTEzMzQ4ODkxMDQ5NjQ0ODEzNzE4MDE4IiwiMjMiLCIyNzc1Mjc2NjgyMzM3MTQ3MTQwODI0ODIyNTcwODY4MTMxMzc2NDg2NjIzMTY1NTE4NzM2NjA3MTg4MTA3MDkxODk4NDQ3MTA0MiIsIjIxNTQ1NzY4ODgzNTA5NjU3MzQwMjA5MTcxNTQ5NDQxMDA1NjAzMzA2MDEyNTEzOTMyMjIxMzcxNTk5NTAxNDk4NTM0ODA3NzE5Njg5IiwiMSIsIjIxNTQ1NzY4ODgzNTA5NjU3MzQwMjA5MTcxNTQ5NDQxMDA1NjAzMzA2MDEyNTEzOTMyMjIxMzcxNTk5NTAxNDk4NTM0ODA3NzE5Njg5IiwiMTY3OTMyMzAzOCIsIjMzNjYxNTQyMzkwMDkxOTQ2NDE5MzA3NTU5Mjg1MDQ4MzcwNDYwMCIsIjAiLCIxNzAwMjQzNzExOTQzNDYxODc4MzU0NTY5NDYzMzAzODUzNzM4MDcyNjMzOTk5NDI0NDY4NDM0ODkxMzg0NDkyMzQyMjQ3MDgwNjg0NCIsIjAiLCI1IiwiODQwIiwiMTIwIiwiMzQwIiwiNTA5IiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIl19XX19.eyJwcm9vZiI6eyJwaV9hIjpbIjcwMjI2MTEzODk5MzY1MDEzNDI2NTkwMjQ2Njk0NTczNTA3OTUwMTU5ODkzOTI1NzAzMDMwODQ4MzcyMTQ4MDc1MzYyNDg4NTE5MzYiLCIxMzg1OTcwODc3NTU0Mzk0Mjk3MTYxNTcxNTA1MTczNjM4MTc4NTEzODkzMjQ3ODc1Mzg3MjU5MTU0NDQxODk1ODkwOTU2MDQyOTU3NCIsIjEiXSwicGlfYiI6W1siMTE1MzQ5NjMxNDgwODQ0OTk0NDg5MDc3NzQxMTMxNjg1OTEyNDYyMjQ4OTg0MTU4ODAwMzY5NTA1MDYyMjU0ODkyMDA1NTc2NTA2NjUiLCIxNDA3MjA4Mjk1MTQ0Njc5NDk5MDk4NDcwNTE3ODA1OTY2NjI4NzM1NTEwNjc5MzUwMTg5MTE2ODgwNjE2NjUwMTUxMDkzMDY0MzQ0MSJdLFsiNDY3ODgyNDc3ODQ5ODA0NzE2OTEzNTk2NTg3MTYwNDgzNjkwMTQ1NjI5MDQ0NjQ0NjUzMzEyNzUwOTU4Mzg5MDU5MDkzNTY5ODQxNCIsIjEyODE5NzMwNTMyMDg0MTM4NDI0ODQ0MjExNDg4NjcxMTUyNDgwOTU1MzQ0MTA2NzU4NTE3NDEzODAxOTIzNTM3OTU3MzYzOTgwMjA0Il0sWyIxIiwiMCJdXSwicGlfYyI6WyIxNTUyMDYzNjk4OTY2MTg3NzExNDUwNjkwNDgxMDQxMzExNDI4NzQ5ODE1OTk2NDA5OTU2MTY5ODUyNjc4MzUwMDE1NjU1MjQzMDAwNCIsIjEyNjkyNzA3NDA3MTczMDg0OTM5NzQ1ODU5NzE0ODMxNDYyMDQ1ODg5NDA4NTk4NTI3MjU0ODA3NzkwNDk0NDY2Mjc5Njg3ODU5MjQ3IiwiMSJdLCJwcm90b2NvbCI6Imdyb3RoMTYiLCJjdXJ2ZSI6ImJuMTI4In0sInB1Yl9zaWduYWxzIjpbIjI3MTUyNjc2OTg3MTI4NTQyMDY2ODA4NTkxOTk4NTczMDAwMzcwNDM2NDY0NzIyNTE5NTEzMzQ4ODkxMDQ5NjQ0ODEzNzE4MDE4IiwiMTIxODQ5NzQwNzE0Mjc3NjgzNTIwMjcwMDM4NzgzMTkzMzgyNDkzODM4NDYxNjQ3MzAyMDQ1MDUzMjY5NTM1NTA2NDczOTExNzg4MDAiLCI4NzU2MDYwMjA1MDg2ODAzMzM1MjUyMzE5NzQ4NzQ4MzU0NzYxOTYxODE0MDEyNzI1NDk5ODczMzgyOTg4MDU2NDE4NjgwNjI4NjE5Il19`

	schemaLoader := &mockJSONLDSchemaLoader{}
	authInstance, err := NewVerifier(verificationKeyloader, stateResolvers,
		WithDocumentLoader(schemaLoader))
	require.NoError(t, err)
	parsedToken, err := authInstance.VerifyJWZ(context.Background(), token)
	require.NoError(t, err)
	require.Equal(t, parsedToken.Alg, "groth16")
	schemaLoader.assert(t)
}

func TestVerifier_FullVerify(t *testing.T) {
	// request
	verifierID := "did:polygonid:polygon:mumbai:2qJ689kpoJxcSzB5sAFJtPsSBSrHF5dq722BHMqURL"
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

	schemaLoader := &mockJSONLDSchemaLoader{
		schemas: map[string]string{
			"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld": loadSchema("kyc-v3.json-ld"),
		},
	}
	authInstance, err := NewVerifier(verificationKeyloader, stateResolvers,
		WithDocumentLoader(schemaLoader))
	require.NoError(t, err)
	_, err = authInstance.FullVerify(context.Background(), token, request, pubsignals.WithAcceptedProofGenerationDelay(proofGenerationDelay))
	require.NoError(t, err)
	schemaLoader.assert(t)
}

func TestVerifier_FullVerify_JWS(t *testing.T) {
	var request protocol.AuthorizationRequestMessage

	var sigReq protocol.ZeroKnowledgeProofRequest
	sigReq.ID = 1
	sigReq.CircuitID = string(circuits.AtomicQuerySigV2CircuitID)
	opt := true
	sigReq.Optional = &opt
	sigReq.Query = map[string]interface{}{
		"allowedIssuers": []string{"*"},
		"credentialSubject": map[string]interface{}{
			"birthday": map[string]interface{}{
				"$lt": 20000101,
			},
		},
		"context": "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v4.jsonld",
		"type":    "KYCAgeCredential",
	}
	request.Body.Scope = append(request.Body.Scope, sigReq)
	request.From = "did:polygonid:polygon:mumbai:2qLPqvayNQz9TA2r5VPxUugoF18teGU583zJ859wfy"
	request.To = "did:polygonid:polygon:mumbai:2qEevY9VnKdNsVDdXRv3qSLHRqoMGMRRdE5Gmc6iA7"

	token := `eyJhbGciOiJFUzI1NkstUiIsImtpZCI6ImRpZDpwa2g6cG9seToweDcxNDFFNGQyMEY3NjQ0REM4YzBBZENBOGE1MjBFQzgzQzZjQUJENjUjUmVjb3ZlcnkyMDIwIiwidHlwIjoiYXBwbGljYXRpb24vaWRlbjNjb21tLXNpZ25lZC1qc29uIn0.eyJpZCI6IjJjOGQ5NzQ3LTQ0MTAtNGU5My1iZjg0LTRlYTNjZmY4MmY0MCIsInR5cCI6ImFwcGxpY2F0aW9uL2lkZW4zY29tbS1zaWduZWQtanNvbiIsInR5cGUiOiJodHRwczovL2lkZW4zLWNvbW11bmljYXRpb24uaW8vYXV0aG9yaXphdGlvbi8xLjAvcmVzcG9uc2UiLCJ0aGlkIjoiN2YzOGExOTMtMDkxOC00YTQ4LTlmYWMtMzZhZGZkYjhiNTQyIiwiYm9keSI6eyJzY29wZSI6W3siaWQiOjEsImNpcmN1aXRJZCI6ImNyZWRlbnRpYWxBdG9taWNRdWVyeVNpZ1YyIiwicHJvb2YiOnsicGlfYSI6WyIxMzI3Njk4Nzc5MjQ5MjM0OTA2MDcxMDc3NTEyOTUxMjYxNzY1NjMzODcxMDkxMzE3NDA0NzE0NTcyMDY4Mjk4NzU0MzUwNjY3NDY0IiwiMjA1NDcyOTI1MzQ0MDgxNzA4NDQwODc3MzY2MDQ0OTYyNjQ3MzI2NjUxNDkxMDEzMzMxNzk3NTg5NTAwMjM0NTgwMjA1Njg5NzMzNTYiLCIxIl0sInBpX2IiOltbIjcyNTI1MDEyNjE5ODM1NTYwMjM1NjA3MzI1MjIzODk2MjIxMDY4MTA5OTUxNzkxNjI0MjY2NzcyNDM2MjQwNTQ0Mzc2Nzc1ODI4MCIsIjgyNDU2MTQzMTExNjUzNTUyNzcyNTgyNTg1NTA0MTI5MTUzNjAzNTc2MjEyMDY5OTA0Mjk3NTE3ODk2NTgwNTI1ODY0Mjc2NjgyMDMiXSxbIjg0MjA4OTI3MTI5OTMyMTU5OTU3NjkwMDQ3MzU2Njc5MzY3MDk4MzY5MTY4MzU4MDM2Njc2NjI1NzQxMTcyNjEzNjI2OTgxMzI1MjkiLCIxMDgyOTQzMjI5MDkyODY3MjM1NjAzNjExMTgxNjE4NTQ0MDU3NTgwMDI1NDQzODAyMzUzNTA3MzUzNTY1ODMzOTE0MzMzODAzNDAyNyJdLFsiMSIsIjAiXV0sInBpX2MiOlsiMTIwNTc1NzM1NDQ2Mzc1NDA1MzE2MjIxNDc2NDg2NjE0MDc1NzM1MzY2MjU0MjM0MzY1ODE0MTk2OTY3NzYwOTMxOTY5Nzc5OTg2MzkiLCIxNTIwMzMwMjIxNjcyOTEzOTcwNjQyNjcyMzc5Mzk5Mjk0MjI5NjY1NTU0NDA4MTEwODkzMTE2MjIwMTQxOTcxNzI0MjU4NTQzOTg2NSIsIjEiXSwicHJvdG9jb2wiOiJncm90aDE2IiwiY3VydmUiOiJibjEyOCJ9LCJwdWJfc2lnbmFscyI6WyIxIiwiMjgwMTg1ODg4MjE0NzE5Mzk2MjQ3MTE0MjE5MjIwNzkzOTU0NTE1MDc3NTQzNzU5Nzg0MDgyMzA1MjQ3OTI3ODY4NjI5OTc1MDMiLCIxNDE5MzMwNDc0NzUwMTMzMTE4MTgwOTcxNTkxMjQ4NzIzNjUyNzAwMzkyNTA4MjEwNjc1MjM3Njc5NjA5OTg5MDIwMTkyODE4NTY5MCIsIjEiLCIyMjk0MjU5NDE1NjI2NjY2NTQyNjYxMzQ2Mjc3MTcyNTMyNzMxNDM4MjY0NzQyNjk1OTA0NDg2MzQ0Njg2NjYxMzAwMzc1MTkzOCIsIjEiLCIzMTY5NjEyMzY4MDg3OTA1MzQyNzg2NTE0MDk5NDQ5Mjk3NDA0MzgzODc0MzcxMzU2OTI0ODI4MDgyMTQzNjExOTUzNjIxODU5NzU5IiwiMTY4NzQzMzc0OCIsIjI2NzgzMTUyMTkyMjU1ODAyNzIwNjA4MjM5MDA0MzMyMTc5Njk0NCIsIjAiLCIyMDM3NjAzMzgzMjM3MTEwOTE3NzY4MzA0ODQ1NjAxNDUyNTkwNTExOTE3MzY3NDk4NTg0MzkxNTQ0NTYzNDcyNjE2NzQ1MDk4OTYzMCIsIjIiLCIyIiwiMjAwMDAxMDEiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiXX1dfSwiZnJvbSI6ImRpZDpwa2g6cG9seToweDcxNDFFNGQyMEY3NjQ0REM4YzBBZENBOGE1MjBFQzgzQzZjQUJENjUiLCJ0byI6ImRpZDpwb2x5Z29uaWQ6cG9seWdvbjptdW1iYWk6MnFMUHF2YXlOUXo5VEEycjVWUHhVdWdvRjE4dGVHVTU4M3pKODU5d2Z5In0.bWc2ECABj7nvHatD8AXWNJM2VtfhkIjNwz5BBIK9zBMsP0-UWLEWdAWcosiLkYoL0KWwZpgEOrPPepl6T5gC-AA`

	schemaLoader := &mockJSONLDSchemaLoader{schemas: map[string]string{
		"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v4.jsonld": loadSchema("kyc-v4.json-ld"),
	}}

	mockedResolver := func(did string) (*verifiable.DIDDocument, error) {
		if did != "did:pkh:poly:0x7141E4d20F7644DC8c0AdCA8a520EC83C6cABD65" {
			return nil, errors.Errorf("unexpected DID: %v", did)
		}
		data := `{"@context":["https://www.w3.org/ns/did/v1",{"EcdsaSecp256k1RecoveryMethod2020":"https://identity.foundation/EcdsaSecp256k1RecoverySignature2020#EcdsaSecp256k1RecoveryMethod2020","blockchainAccountId":"https://w3id.org/security#blockchainAccountId"}],"id":"did:pkh:poly:0x7141E4d20F7644DC8c0AdCA8a520EC83C6cABD65","verificationMethod":[{"id":"did:pkh:poly:0x7141E4d20F7644DC8c0AdCA8a520EC83C6cABD65#Recovery2020","type":"EcdsaSecp256k1RecoveryMethod2020","controller":"did:pkh:poly:0x7141E4d20F7644DC8c0AdCA8a520EC83C6cABD65","blockchainAccountId":"eip155:137:0x7141E4d20F7644DC8c0AdCA8a520EC83C6cABD65"}],"authentication":["did:pkh:poly:0x7141E4d20F7644DC8c0AdCA8a520EC83C6cABD65#Recovery2020"],"assertionMethod":["did:pkh:poly:0x7141E4d20F7644DC8c0AdCA8a520EC83C6cABD65#Recovery2020"]}`
		var doc verifiable.DIDDocument
		err := json.Unmarshal([]byte(data), &doc)
		if err != nil {
			return nil, err
		}
		return &doc, nil
	}

	v, err := NewVerifier(verificationKeyloader, stateResolvers,
		WithDocumentLoader(schemaLoader),
		WithDIDResolver(mockedResolver))
	require.NoError(t, err)
	_, err = v.FullVerify(context.Background(), token, request, pubsignals.WithAcceptedProofGenerationDelay(proofGenerationDelay))
	require.NoError(t, err)

	schemaLoader.assert(t)
}

func TestVerifyAuthResponseWithEmptyReq(t *testing.T) {
	verifierID := "did:polygonid:polygon:mumbai:2qEevY9VnKdNsVDdXRv3qSLHRqoMGMRRdE5Gmc6iA7"
	callbackURL := "https://test.com/callback"
	reason := "test"

	userID := "did:polygonid:polygon:mumbai:2qCjgvM5XKq1dSxcaVD4tUPg84wHAGEfRAy6pnvL8J"
	var zkReq protocol.ZeroKnowledgeProofRequest
	zkReq.ID = 84239
	zkReq.CircuitID = string(circuits.AtomicQuerySigV2CircuitID)
	opt := true
	zkReq.Optional = &opt
	zkReq.Query = map[string]interface{}{
		"allowedIssuers": []string{"*"},
		"context":        "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-nonmerklized.jsonld",
		"type":           "KYCAgeCredential",
	}

	authReq := CreateAuthorizationRequestWithMessage(reason, "test", verifierID, callbackURL)
	authReq.Body.Scope = append(authReq.Body.Scope, zkReq)
	authReq.ID = "28494007-9c49-4f1a-9694-7700c08865bf"
	authReq.ThreadID = "7f38a193-0918-4a48-9fac-36adfdb8b542"

	// response
	resp := protocol.AuthorizationResponseMessage{
		ID:       "84239",
		Typ:      "application/iden3comm-plain-json",
		Type:     "https://iden3-communication.io/authorization/1.0/response",
		ThreadID: authReq.ThreadID,
		Body: protocol.AuthorizationMessageResponseBody{
			Message: "test",
			Scope: []protocol.ZeroKnowledgeProofResponse{
				{
					ID:        84239,
					CircuitID: string(circuits.AtomicQuerySigV2CircuitID),
					ZKProof: types.ZKProof{
						Proof: &types.ProofData{
							A: []string{
								"12438986486122571189252917917494589996381439858584898996374967683395269730731",
								"9412079662468735177603233699455634208465878005774236161008642218316734804796",
								"1",
							},
							B: [][]string{
								{
									"12705378067840438230602790810116303665597242623604828384033131906209301383932",
									"8051172734575096778884550333111728898496153961669774926620891253970840750743",
								},
								{
									"16749240419593841408185262492070297370295714176340637165233273033868360979018",
									"2999000186136809474865219897229258765249288247905601316016410459032164165331",
								},
								{
									"1",
									"0",
								}},
							C: []string{
								"12139245376011507438715230756679171548416792518380038781634231898718436149353",
								"5615427094043590964226038096439342195435404664699787454067611877169392904955",
								"1",
							},
							Protocol: "groth16",
						},
						PubSignals: []string{
							"0",
							"19643426216833902904490317766780826367730928250958458340547064713091289602",
							"3684990652514203763871876082267216309378204238417321809966225547084716893577",
							"84239",
							"27434661371051334799078615742064517792049501374373415671506754318297010690",
							"1",
							"3684990652514203763871876082267216309378204238417321809966225547084716893577",
							"1694785732",
							"198285726510688200335207273836123338699",
							"1",
							"0",
							"6",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
							"0",
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

	schemaLoader := &mockJSONLDSchemaLoader{
		schemas: map[string]string{
			"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-nonmerklized.jsonld": loadSchema("kyc-nonmerklized.jsonld"),
		},
	}
	authInstance, err := NewVerifier(verificationKeyloader, stateResolvers,
		WithDocumentLoader(schemaLoader))
	require.NoError(t, err)
	err = authInstance.VerifyAuthResponse(context.Background(), resp, authReq,
		pubsignals.WithAcceptedProofGenerationDelay(proofGenerationDelay))
	require.NoError(t, err)
	schemaLoader.assert(t)
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
	verifierID := "did:polygonid:polygon:mumbai:2qJ689kpoJxcSzB5sAFJtPsSBSrHF5dq722BHMqURL"
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

	schemaLoader := &mockJSONLDSchemaLoader{
		schemas: map[string]string{
			"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v4.jsonld": loadSchema("kyc-v4.json-ld"),
			"https://www.w3.org/2018/credentials/v1":                                                        loadSchema("credentials-v1.json-ld"),
		},
	}
	authInstance, err := NewVerifier(verificationKeyloader, stateResolvers,
		WithDocumentLoader(schemaLoader))
	require.NoError(t, err)
	_, err = authInstance.FullVerify(context.Background(), token, request, pubsignals.WithAcceptedProofGenerationDelay(proofGenerationDelay))
	require.NoError(t, err)
	schemaLoader.assert(t)
}

func TestEmptyCredentialSubject(t *testing.T) {
	// request
	verifierID := "did:polygonid:polygon:mumbai:2qJ689kpoJxcSzB5sAFJtPsSBSrHF5dq722BHMqURL"
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

	schemaLoader := &mockJSONLDSchemaLoader{
		schemas: map[string]string{
			"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v101.json-ld": loadSchema("kyc-v101.json-ld"),
		},
	}
	authInstance, err := NewVerifier(verificationKeyloader, stateResolvers,
		WithDocumentLoader(schemaLoader))
	require.NoError(t, err)
	_, err = authInstance.FullVerify(context.Background(), token, request, pubsignals.WithAcceptedProofGenerationDelay(proofGenerationDelay))
	require.NoError(t, err)

	schemaLoader.assert(t)
}

func loadSchema(name string) string {
	bs, err := os.ReadFile("testdata/" + name)
	if err != nil {
		panic(err)
	}
	return string(bs)
}

func TestVerifyV3MessageWithSigProof_NonMerklized(t *testing.T) {
	verifierID := "did:polygonid:polygon:mumbai:2qEevY9VnKdNsVDdXRv3qSLHRqoMGMRRdE5Gmc6iA7"
	callbackURL := "https://test.com/callback"
	reason := "test"

	var mtpProofRequest protocol.ZeroKnowledgeProofRequest
	mtpProofRequest.ID = 1
	mtpProofRequest.CircuitID = string(circuits.AtomicQueryV3CircuitID)
	opt := true
	mtpProofRequest.Optional = &opt
	mtpProofRequest.Query = map[string]interface{}{
		"allowedIssuers": []string{"*"},
		"credentialSubject": map[string]interface{}{
			"documentType": map[string]interface{}{
				"$eq": 99,
			},
		},
		"context":   "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-nonmerklized.jsonld",
		"type":      "KYCAgeCredential",
		"proofType": "BJJSignature2021",
	}
	request := CreateAuthorizationRequestWithMessage(reason, "message to sign", verifierID, callbackURL)
	request.Body.Scope = append(request.Body.Scope, mtpProofRequest)

	userID := "did:iden3:polygon:mumbai:wuw5tydZ7AAd3efwEqPprnqjiNHR24jqruSPKmV1V"
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
							"21151810189677517948470349663375124644397774196647400403099596802180335321041",
							"9696355494050033680997427331681865862422534743502124664674316367271074647154",
							"1",
						},
						B: [][]string{
							{
								"16506537758980670869571638619482799907832786754264203096530594327503427638349",
								"21622856063735476578181075235629493936632210758028392094000175452997617174729",
							},
							{
								"3541099173356890506571047958641755303967119354297594276262862768415334431356",
								"10602931525454211449997603492083254084178062784908411330998719756785213529232",
							},
							{
								"1",
								"0",
							}},
						C: []string{
							"18500987823675051898831616007808039359308350085444553101353022992087458949277",
							"16300345856950383026668416507066891269452696183122072516138872408963944059219",
							"1",
						},
						Protocol: "groth16",
					},
					PubSignals: []string{
						"0",
						"21568225469889458305914841490175280093555015071329787375641431262509208065",
						"4487386332479489158003597844990487984925471813907462483907054425759564175341",
						"0",
						"0",
						"0",
						"1",
						"1",
						"25191641634853875207018381290409317860151551336133597267061715643603096065",
						"1",
						"4487386332479489158003597844990487984925471813907462483907054425759564175341",
						"1708627573",
						"198285726510688200335207273836123338699",
						"1",
						"0",
						"3",
						"1",
						"99",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"1",
						"0",
						"0",
					},
				},
			},
		},
	}

	schemaLoader := &mockJSONLDSchemaLoader{
		schemas: map[string]string{
			"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-nonmerklized.jsonld": loadSchema("kyc-nonmerklized.jsonld"),
		},
	}
	authInstance, err := NewVerifier(verificationKeyloader, stateResolvers,
		WithDocumentLoader(schemaLoader))
	require.NoError(t, err)
	err = authInstance.VerifyAuthResponse(context.Background(), message, request,
		pubsignals.WithAcceptedProofGenerationDelay(proofGenerationDelay),
	)
	require.Nil(t, err)
	schemaLoader.assert(t)
}

func TestVerifyV3MessageWithMtpProof_Merklized(t *testing.T) {
	verifierID := "did:polygonid:polygon:mumbai:2qEevY9VnKdNsVDdXRv3qSLHRqoMGMRRdE5Gmc6iA7"
	callbackURL := "https://test.com/callback"
	reason := "test"

	var mtpProofRequest protocol.ZeroKnowledgeProofRequest
	mtpProofRequest.ID = 1
	mtpProofRequest.CircuitID = string(circuits.AtomicQueryV3CircuitID)
	opt := true
	mtpProofRequest.Optional = &opt
	mtpProofRequest.Query = map[string]interface{}{
		"allowedIssuers": []string{"*"},
		"credentialSubject": map[string]interface{}{
			"documentType": map[string]interface{}{
				"$eq": 99,
			},
		},
		"context":   "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
		"type":      "KYCAgeCredential",
		"proofType": "Iden3SparseMerkleTreeProof",
	}

	request := CreateAuthorizationRequestWithMessage(reason, "message to sign", verifierID, callbackURL)
	request.Body.Scope = append(request.Body.Scope, mtpProofRequest)

	userID := "did:iden3:polygon:mumbai:wuw5tydZ7AAd3efwEqPprnqjiNHR24jqruSPKmV1V"
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
							"3763096690871993752230144382333919266676597557177411717784644613717115469090",
							"10028320366827736122969323296605756343373454834156702791274611491480096283778",
							"1",
						},
						B: [][]string{
							{
								"10203840113383841789860152028711536726169998029835635775567253548408092915572",
								"18114537333654513143039191206627336787000523946155884037749310624596117473712",
							},
							{
								"12017396115161816147831100165808412964134386241428880233984090164219496714397",
								"819630053285309842273190416121178576498258493837857641483373291509348418081",
							},
							{
								"1",
								"0",
							}},
						C: []string{
							"12280809699865713488550660734203114688285519767013704349296208589786741809007",
							"17346425160089185216966296588854077581247196532430671131272276524525659173700",
							"1",
						},
						Protocol: "groth16",
					},
					PubSignals: []string{
						"1",
						"21568225469889458305914841490175280093555015071329787375641431262509208065",
						"18909715826522346236105065343536699741230963116333195096070429245132708636972",
						"0",
						"0",
						"0",
						"2",
						"1",
						"19898531390599208021876718705689344940605246460654065917270282371355906561",
						"1",
						"5224437024673068498206105743424598123651101873588696368477339341771571761791",
						"1708627799",
						"74977327600848231385663280181476307657",
						"0",
						"17040667407194471738958340146498954457187839778402591036538781364266841966",
						"0",
						"1",
						"99",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"0",
						"1",
						"0",
						"0",
					},
				},
			},
		},
	}

	schemaLoader := &mockJSONLDSchemaLoader{
		schemas: map[string]string{
			"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld": loadSchema("kyc-v3.json-ld"),
		},
	}
	authInstance, err := NewVerifier(verificationKeyloader, stateResolvers,
		WithDocumentLoader(schemaLoader))
	require.NoError(t, err)
	err = authInstance.VerifyAuthResponse(context.Background(), message, request,
		pubsignals.WithAcceptedProofGenerationDelay(proofGenerationDelay))
	require.Nil(t, err)
	schemaLoader.assert(t)
}

func TestFullVerifyLinkedProofsVerification(t *testing.T) {
	verifierID := "did:iden3:polygon:mumbai:wzokvZ6kMoocKJuSbftdZxTD6qvayGpJb3m4FVXth"
	callbackURL := "https://test.com/callback"
	reason := "test"

	request := CreateAuthorizationRequestWithMessage(reason, "mesage", verifierID, callbackURL)

	var mtpProofRequest1 protocol.ZeroKnowledgeProofRequest
	mtpProofRequest1.ID = 1
	mtpProofRequest1.CircuitID = string(circuits.AtomicQueryV3CircuitID)
	opt := false
	mtpProofRequest1.Optional = &opt
	mtpProofRequest1.Query = map[string]interface{}{
		"allowedIssuers": []string{"*"},
		"credentialSubject": map[string]interface{}{
			"documentType": map[string]interface{}{
				"$eq": 99,
			},
		},
		"context":   "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-nonmerklized.jsonld",
		"type":      "KYCAgeCredential",
		"proofType": "BJJSignature2021",
	}

	var mtpProofRequest2 protocol.ZeroKnowledgeProofRequest
	mtpProofRequest2.ID = 2
	mtpProofRequest2.CircuitID = string(circuits.LinkedMultiQuery10CircuitID)
	mtpProofRequest2.Optional = &opt
	mtpProofRequest2.Query = map[string]interface{}{
		"groupId":        1,
		"allowedIssuers": []string{"*"},
		"credentialSubject": map[string]interface{}{
			"documentType": map[string]interface{}{
				"$eq": 1,
			},
			"position": map[string]interface{}{
				"$eq": "boss",
				"$ne": "employee",
			},
		},
		"context":   "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v101.json-ld",
		"type":      "KYCEmployee",
		"proofType": "Iden3SparseMerkleTreeProof",
	}

	var mtpProofRequest3 protocol.ZeroKnowledgeProofRequest
	mtpProofRequest3.ID = 3
	mtpProofRequest3.CircuitID = string(circuits.AtomicQueryV3CircuitID)
	mtpProofRequest3.Optional = &opt
	mtpProofRequest3.Params = map[string]interface{}{
		"nullifierSessionId": "12345",
	}

	mtpProofRequest3.Query = map[string]interface{}{
		"groupId":        1,
		"allowedIssuers": []string{"*"},
		"credentialSubject": map[string]interface{}{
			"hireDate": map[string]interface{}{
				"$eq": "2023-12-11",
			},
		},
		"context":                  "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v101.json-ld",
		"type":                     "KYCEmployee",
		"skipClaimRevocationCheck": true,
		"proofType":                "BJJSignature2021",
	}
	request.Body.Scope = append(append(append(request.Body.Scope, mtpProofRequest1), mtpProofRequest2), mtpProofRequest3)

	schemaLoader := &mockJSONLDSchemaLoader{
		schemas: map[string]string{
			"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v101.json-ld":        loadSchema("kyc-v101.json-ld"),
			"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-nonmerklized.jsonld": loadSchema("kyc-nonmerklized.jsonld"),
		},
	}
	authInstance, err := NewVerifier(verificationKeyloader, stateResolvers,
		WithDocumentLoader(schemaLoader))
	require.NoError(t, err)

	tokenString := "eyJhbGciOiJncm90aDE2IiwiY2lyY3VpdElkIjoiYXV0aFYyIiwiY3JpdCI6WyJjaXJjdWl0SWQiXSwidHlwIjoiYXBwbGljYXRpb24vaWRlbjMtemtwLWpzb24ifQ.eyJpZCI6ImQyMmMyM2ExLTBmMDMtNDhlNS04MTM4LTE3MTc3Y2ZmNDJhNyIsInR5cCI6ImFwcGxpY2F0aW9uL2lkZW4zLXprcC1qc29uIiwidHlwZSI6Imh0dHBzOi8vaWRlbjMtY29tbXVuaWNhdGlvbi5pby9hdXRob3JpemF0aW9uLzEuMC9yZXNwb25zZSIsInRoaWQiOiI0ZjNlYTUxYy0zZDI3LTQxOTMtYmM2NC0xZjk2NDIxZTk2NWEiLCJib2R5Ijp7Im1lc3NhZ2UiOiJtZXNhZ2UiLCJzY29wZSI6W3siaWQiOjEsImNpcmN1aXRJZCI6ImNyZWRlbnRpYWxBdG9taWNRdWVyeVYzLWJldGEuMSIsInByb29mIjp7InBpX2EiOlsiMTU4NTc2NzI4MjQ3Mzc4MjgwMzIwNjUxMzIyMzIzNDg0OTI3MjQ5OTUyMDUzOTc1MTMwNjE5MjcwNTQzNTcwNDk5NzkxNjQ0MTg0NTQiLCIxNjg2MDYyMzUzNDk3MTU2Mzc5MzMxMzMzMDcyMTg0MjYxNzk0NjcwNTg2MzMwNjkxNjk1OTM5NDkwOTQzOTk4MzMxODAxMzc2MDY0NCIsIjEiXSwicGlfYiI6W1siMjAxOTgxMjA5MDk3NDc3MzE5NjMyODc1Mjk4MzIzOTg3MzI1MzE2ODU2NzQ4MDcyODM5OTczNzA5Mjg3MzM4NTEzMTU5NjQ3Njc4NTgiLCI0NjY4NzM0ODM1NTE1MzA3NzM5MjE0NDI1Njk3NDc0NzEzNjYxODQzNTU4NTMwMjcwMzExMTU5NjExODQzMDM4NDk0MzUxNjk5NDA0Il0sWyIxMTM1NzM4NDY1OTQwNDk1Mjg2MDUzNzg3NjA3MzA1Mzk2NzI1OTI1MzMwMzE3MjA1NzgwODAwMDQ0NDM3ODYwMTgyNDI2NTYzNjI0MiIsIjM0NDM4MDc4MzgwNTg4ODU3ODMyNjA3Mzg3NzEzODYxMjk0NDE5ODcyMTM0OTk1Mzc5NTk3NjkyMjE1NDcyNTc2MDk4NjM2MzcwNiJdLFsiMSIsIjAiXV0sInBpX2MiOlsiMTE3NDc0MjE4MDY5Mjk1Mzc0ODM3NzMyNjI2OTY5OTYxMzc3NTM4Mzk1OTQyOTIzODU5Mjk1MTk4NTIwOTEwMDA3ODk4NzIxMzI4OTUiLCIyMzA5NzgwNzA5ODk3NzkwNTg0MzY3NTY2OTI1MzQ0MDA3ODAyMTg2NjgwNzU5Njg4MjAzMzQ2MjE5OTk3NjY1OTczMjE1MTk0NjA4IiwiMSJdLCJwcm90b2NvbCI6Imdyb3RoMTYiLCJjdXJ2ZSI6ImJuMTI4In0sInB1Yl9zaWduYWxzIjpbIjAiLCIyMTU2ODIyNTQ2OTg4OTQ1ODMwNTkxNDg0MTQ5MDE3NTI4MDA5MzU1NTAxNTA3MTMyOTc4NzM3NTY0MTQzMTI2MjUwOTIwODA2NSIsIjQ0ODczODYzMzI0Nzk0ODkxNTgwMDM1OTc4NDQ5OTA0ODc5ODQ5MjU0NzE4MTM5MDc0NjI0ODM5MDcwNTQ0MjU3NTk1NjQxNzUzNDEiLCIwIiwiMCIsIjAiLCIxIiwiMSIsIjI1MTkxNjQxNjM0ODUzODc1MjA3MDE4MzgxMjkwNDA5MzE3ODYwMTUxNTUxMzM2MTMzNTk3MjY3MDYxNzE1NjQzNjAzMDk2MDY1IiwiMSIsIjQ0ODczODYzMzI0Nzk0ODkxNTgwMDM1OTc4NDQ5OTA0ODc5ODQ5MjU0NzE4MTM5MDc0NjI0ODM5MDcwNTQ0MjU3NTk1NjQxNzUzNDEiLCIxNzA4Njc5MzIwIiwiMTk4Mjg1NzI2NTEwNjg4MjAwMzM1MjA3MjczODM2MTIzMzM4Njk5IiwiMSIsIjAiLCIzIiwiMSIsIjk5IiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMSIsIjI1MTkxNjQxNjM0ODUzODc1MjA3MDE4MzgxMjkwNDA5MzE3ODYwMTUxNTUxMzM2MTMzNTk3MjY3MDYxNzE1NjQzNjAzMDk2MDY1IiwiMCJdfSx7ImlkIjoyLCJjaXJjdWl0SWQiOiJsaW5rZWRNdWx0aVF1ZXJ5MTAtYmV0YS4xIiwicHJvb2YiOnsicGlfYSI6WyIxMjU1OTcwOTI3MDE2OTY2NTY3ODc1ODkyNDI5Nzg1NTMxNzc4NTY0NzI3ODQxNTgxMzYyODIzMDExMjc1MzE2NjgwODU2NDYzODA0MyIsIjExNDg2Njc5NDkyNzg2MDcyODE1NzkzNzQ4Nzg5MjMxNjM2MDQ1Njc1NDUxNzA3MjQ0MTgwMjkwMDI1Mzc0MzMyODY4NDMwMzMxNjU5IiwiMSJdLCJwaV9iIjpbWyI3NjUyMTY2NjYwMjIyOTY0MjQzNjc5MjM5NTUzMDM2OTExMzA3ODc1MTg3MjY3MDgwNTEyOTIzNDQ2MDU4NjY5NjUwMDIyNTk2MTg1IiwiNTAzNjc2MDIxNjU4NTk2NzkzNzY2NTIxNTU5NzAyNTIyMDc3MjAwNDQ3MDk2MDcxNzYyMjg3NDIxMjQ0Mjk1NTA0OTE1MTcwOTU3MSJdLFsiMjEzMzI2NjY0NzU1OTc1MjAzODEwNzY5NTc4ODA4ODU2ODgyOTI2ODU1MDgzNDcwMTE5NjI0Mjk3MTk2NTkxNjU0MDc1NzQzMjA5NDkiLCIxMTgxODk2MDg5Njg2MzcwOTA5NzgyNjE5MzI0MDM0MDkyMTc1MDMwMzEwMTE4MDU4NzEwMjk0Njg3OTA0MDAxNjUyODMxNjIyMjc4NSJdLFsiMSIsIjAiXV0sInBpX2MiOlsiMTkyNzMzNTQ5MzEyODYzNTIwODgwMjMwNzAyMTIzNDA2OTc2Njg3MDQ2NDQyNjUxNDA2ODY3Nzk2NTMzNTAzMzM0MTAzMjE0ODk2NjkiLCIxNzE1NDk4NjQ5MTgwMzkyNDMxNjIzMDQxNTc5NjYzMDY1OTMyMTQ2NDcyODMxMzIwMDYzNzY5MTg5MDM0MTQyMTU5NDgzMzYyMjY2NyIsIjEiXSwicHJvdG9jb2wiOiJncm90aDE2IiwiY3VydmUiOiJibjEyOCJ9LCJwdWJfc2lnbmFscyI6WyIxMTgyODAxNDU0NjU1MTU5NTU0OTgwOTkwMzYxMTk5NDIxMTQyNTUwNzcxNDg1NjYxNTQyMDk0Njg3OTU2NjQwMjYzMDkxMDE4OTI0IiwiMSIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIxMDM0MTU3NDQ0ODM4NjQ4NTMzODEyNjIxMjY5NDc4OTIyNDY3NjI2MTc5ODE0MDEzMjA0NjQ5NjIwNDczMDQ0Mjc0NjcwNzc0MzM1MCIsIjE0NDYwNzY3OTk1MDIwNDc4MDkzNTMzMTQxNjMxMTgzMDYzODEzMjE5ODY5NTkyNDQ3MDM4MzgxNTExODgxMjMzNzYwNjIyMjA4NzIiLCIzNjQyNzczOTQwNjAxOTcyNDA4NjcyOTkzNDgxNDA1NjI4MTYxODI3NTExNjIyNzAxNTgwMTQyMjQyNjkxMTI3MDIxMTE5ODEwNTk2IiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjEiLCIxIiwiMSIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIxIiwiMSIsIjEiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIl19LHsiaWQiOjMsImNpcmN1aXRJZCI6ImNyZWRlbnRpYWxBdG9taWNRdWVyeVYzLWJldGEuMSIsInByb29mIjp7InBpX2EiOlsiMTUzNjQ1MTk0MTUzOTA4NzEyMjc3ODk4NzQyMTcyODQ2MTM5MTk4MjczNTYwMjM2NzUwNTAzNjY1NDczNjEyMDkzMjQ0NDkzNzQ4NDUiLCI5ODQ4Mzk4MTIyMDA2MDIxMDkzMjYzODQwNjc2ODkzOTY0NTU2ODAwNzk5NzA5NjM2NTM5NTEzNjU4NDU5NDY1MDg2MDk0NDg4MyIsIjEiXSwicGlfYiI6W1siMTAzMDIwMDQzODI5OTIwNDI4MjAzMDM2MDkzMjQ4NjY5NzI5Njk0NTY0NDI3ODU3MDAwNzkyODA1Nzk4NjU5NzM3MzQzODc2MTkyNzEiLCIxODkwMTg1NDMyMzA4NzcyMjk0Njk5OTgwODM2MTQzMTA5MjI4NjM5Mzc4NDQxODg1NDE3NzM0NTk5MjMzNzE2NTU0OTIzNDg1MTI2OCJdLFsiMjgwOTM4ODM3MzA5NTg3MjU0NDI3NDUzODEyOTczNTY3Mjk5MzAwNzEzNzMyNDYxNDE0NzcyMzM5NTEwOTA1NjY3MzI5MTk1MTg2OSIsIjUwMzk4MDMzMDIzNDM3NTg4NDQxMzQwNTA2OTQ2MDY4NTY2NTE3OTM3MDY1MjUxMDY3OTkzODc3OTczMTg5MTE0NTg0ODI1ODE5MDAiXSxbIjEiLCIwIl1dLCJwaV9jIjpbIjExNDE4NjgyNjY2MDIyOTYwNDk5NjA5MTU2NDIwNDY2MDcwNzg3NzIxNTk5NTgyNjEzNTE0NTAyOTIyMzU4MzUzMDExMzc3NjI4NDIwIiwiNzk5ODk4NDQ3MTE5MzA0MTAyNTc2NTU1MDEzODE5OTYwMTQyOTcyMTAwNzI2MDIyMzUxMjIwNzQ4NzIzMzU4MjU5MzMzMTk4NTAxIiwiMSJdLCJwcm90b2NvbCI6Imdyb3RoMTYiLCJjdXJ2ZSI6ImJuMTI4In0sInB1Yl9zaWduYWxzIjpbIjEiLCIyMTU2ODIyNTQ2OTg4OTQ1ODMwNTkxNDg0MTQ5MDE3NTI4MDA5MzU1NTAxNTA3MTMyOTc4NzM3NTY0MTQzMTI2MjUwOTIwODA2NSIsIjQ0ODczODYzMzI0Nzk0ODkxNTgwMDM1OTc4NDQ5OTA0ODc5ODQ5MjU0NzE4MTM5MDc0NjI0ODM5MDcwNTQ0MjU3NTk1NjQxNzUzNDEiLCIxMTgyODAxNDU0NjU1MTU5NTU0OTgwOTkwMzYxMTk5NDIxMTQyNTUwNzcxNDg1NjYxNTQyMDk0Njg3OTU2NjQwMjYzMDkxMDE4OTI0IiwiMjEwNTE4MTY0Mzc3MTE5OTgwMTcyNDkwNTA0NDQyNDQ3Mjc4MDY4NjEwMjU3MDc4MDQ4OTc4MTM5NTE4NDIyODY2OTAzODI0NzI5MjciLCIwIiwiMSIsIjMiLCIyNTE5MTY0MTYzNDg1Mzg3NTIwNzAxODM4MTI5MDQwOTMxNzg2MDE1MTU1MTMzNjEzMzU5NzI2NzA2MTcxNTY0MzYwMzA5NjA2NSIsIjAiLCI0NDg3Mzg2MzMyNDc5NDg5MTU4MDAzNTk3ODQ0OTkwNDg3OTg0OTI1NDcxODEzOTA3NDYyNDgzOTA3MDU0NDI1NzU5NTY0MTc1MzQxIiwiMTcwODY3OTMzNiIsIjIxOTU3ODYxNzA2NDU0MDAxNjIzNDE2MTY0MDM3NTc1NTg2NTQxMiIsIjAiLCIxMjk2MzUxNzU4MjY5MDYxMTczMzE3MTA1MDQxOTY4MDY3MDc3NDUxOTE0Mzg2MDg2MjIyOTMxNTE2MTk5MTk0OTU5ODY5NDYzODgyIiwiMCIsIjEiLCIxNzAyMjUyODAwMDAwMDAwMDAwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMSIsIjI1MTkxNjQxNjM0ODUzODc1MjA3MDE4MzgxMjkwNDA5MzE3ODYwMTUxNTUxMzM2MTMzNTk3MjY3MDYxNzE1NjQzNjAzMDk2MDY1IiwiMTIzNDUiXX1dfSwiZnJvbSI6ImRpZDppZGVuMzpwb2x5Z29uOm11bWJhaTp3dXc1dHlkWjdBQWQzZWZ3RXFQcHJucWppTkhSMjRqcXJ1U1BLbVYxViIsInRvIjoiZGlkOmlkZW4zOnBvbHlnb246bXVtYmFpOnd6b2t2WjZrTW9vY0tKdVNiZnRkWnhURDZxdmF5R3BKYjNtNEZWWHRoIn0.eyJwcm9vZiI6eyJwaV9hIjpbIjEzNzIzNzUxNjUzMzk3OTcxMzEzMzk0MjE5NzQ5NDI0NDM4OTAwMDc2MzU2NzY2MTQ2NDU2NTUwNDkzMzg3MDMxMjg3NTY4Mjk3MzEwIiwiMTMxMTc2NTQwNzYyMzQ0OTEyNzM4NjE4NTE1MjgzNDc5MTUzNjc4OTM1OTE5ODM3NDAxNTE5NzU3ODcwOTQxMjY2MzM2ODQ5MTA0MzIiLCIxIl0sInBpX2IiOltbIjg5NzM0MjM2ODY3NTE3NzE5NDgxODM2MDg4NDAyMDE1NTUyMjg3MDQxNDM0ODg5NTQ4OTE2OTE0MDc5MDI4MDkzODkyNzAwMTUwODQiLCIxNjYxMzQ3MzA3MjkzOTM3MDg2NTg1ODk2ODg2NjE3MzM4MTYxOTY3MTc0NTY1ODcxNjQ1OTU5MjE0NjE3NTM1MTYzMDMxMTE5ODI1MiJdLFsiMTQ2ODQ3MzU4MzkxNjc1Mzc1MTY1NTk4ODA4NjEzMzI2MTg4MTE2MzY5Nzc3MDc2OTY5ODU5NzU3NjA5MzM1NzY0Nzk4NTE2ODc3MTYiLCI1Njk5NTQ3NTk1NzczNzM0MzU4MDYxMTE4NDc5MjUzMjI3MDE4ODg1MTYzMjMwMjAxMDQ5MDMwNTg1NDI2MjM4MDM4MTY0MjI2MDAwIl0sWyIxIiwiMCJdXSwicGlfYyI6WyIxNDk3NDk1MDc0MzM0NjEzMDUwNDc2MDU3Mzg0MDcxMjA4MDQ3NTU4MDU1ODE3MDU2OTk0OTc3Mjg4Mzk5ODMxNzU3MjI2MjQ5MzQ4MyIsIjgwOTMyOTg0MDQ4OTI0MDAyNTAzMzQxMjU5NDc1NDA2MjU1NTE0MDc2MzQ2NjcyMzY4MjIzMjQ1ODUwMTI2NTI4MTk2OTYxNDYzNzEiLCIxIl0sInByb3RvY29sIjoiZ3JvdGgxNiIsImN1cnZlIjoiYm4xMjgifSwicHViX3NpZ25hbHMiOlsiMjE1NjgyMjU0Njk4ODk0NTgzMDU5MTQ4NDE0OTAxNzUyODAwOTM1NTUwMTUwNzEzMjk3ODczNzU2NDE0MzEyNjI1MDkyMDgwNjUiLCIxMDI5OTA1MDE3OTkwNDc2MTM4MzY4NTg0ODQ5MDU4NTg3NTMxMTQ5NDkyMjI2ODc0NjE1ODk0MTU5NDA0NDUwMzgzMDI5NTI4MTM4MCIsIjAiXX0"
	returnMsg, err := authInstance.FullVerify(context.Background(), tokenString, request, pubsignals.WithAcceptedProofGenerationDelay(proofGenerationDelay))
	require.Nil(t, err)
	require.NotNil(t, returnMsg)
	schemaLoader.assert(t)
}
