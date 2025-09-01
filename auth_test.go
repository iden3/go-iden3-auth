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
	"github.com/iden3/iden3comm/v2/utils"
	"github.com/piprate/json-gold/ld"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	// we have multiimport since two different libraries use the same package
	// with different versions
	// Same issue https://github.com/flashbots/mev-boost-relay/pull/227/files
	_ "github.com/btcsuite/btcd/btcutil"
)

var verificationKeyloader = &loaders.FSKeyLoader{Dir: "./loaders/verification_keys"}

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
	"polygon:amoy":   &mockStateResolver{},
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
							"17986127632500696301936833214834748282118988640054859347393596112177973598393",
							"15534182793610095470902362363419776736277635938508650536729675634576311729692",
							"1",
						},
						B: [][]string{
							{
								"7338497328692675644564987641648502096374251831094372349853229552307345443915",
								"21873896757385838597213325448315031674671530112748272284028350500960284315119",
							},
							{
								"4389053438553442078720421541662069541503079132981369147628609382862358187134",
								"20095077165223345682327215497304961861049068798239033587125849252492655865123",
							},
							{
								"1",
								"0",
							}},
						C: []string{
							"12355121980069068954352772137964392922736350288913506055163839192466777727257",
							"4901524989595691090005671074543010487322868964840164143230262565655073327636",
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
						"1708950663",
						"198285726510688200335207273836123338699",
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
							"1206141210885685268691843620703536170529281542182526987924038407359704226612",
							"4691511460268494838142278955970723189241051700769023850116359155231645962952",
							"1",
						},
						B: [][]string{
							{
								"17879781576554928549561853823635605468659329508512687583360132080392104725081",
								"16542687696560865789172959169248439945717346897794303102535416321225036669286",
							},
							{
								"20570130590431263788504562264597298535240960895316532971597427392983121691924",
								"3942642806293571533235026460473901941304763794877539387371504831161108993517",
							},
							{
								"1",
								"0",
							}},
						C: []string{
							"9166684032773673817826293280569639892136709569644822127576991899707132284865",
							"4138680480162864132088567065899942452840603723378404207898851702927544111679",
							"1",
						},
						Protocol: "groth16",
					},
					PubSignals: []string{
						"1",
						"21568225469889458305914841490175280093555015071329787375641431262509208065",
						"14596903467716034545184185646592839847113415224380360765474057277236021022021",
						"0",
						"0",
						"0",
						"2",
						"1",
						"19898531390599208021876718705689344940605246460654065917270282371355906561",
						"1",
						"5224437024673068498206105743424598123651101873588696368477339341771571761791",
						"1708950776",
						"74977327600848231385663280181476307657",
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

	tokenString := "eyJhbGciOiJncm90aDE2IiwiY2lyY3VpdElkIjoiYXV0aFYyIiwiY3JpdCI6WyJjaXJjdWl0SWQiXSwidHlwIjoiYXBwbGljYXRpb24vaWRlbjMtemtwLWpzb24ifQ.eyJpZCI6IjlmOGM1ZWFmLTc2MWItNDVhMy05MjkxLWU3MTY4MDlhY2U4MCIsInR5cCI6ImFwcGxpY2F0aW9uL2lkZW4zLXprcC1qc29uIiwidHlwZSI6Imh0dHBzOi8vaWRlbjMtY29tbXVuaWNhdGlvbi5pby9hdXRob3JpemF0aW9uLzEuMC9yZXNwb25zZSIsInRoaWQiOiJmMWRiMjM1Ni05ZjQ0LTQ4YWQtOWI3Ni1mODlkNDdmMjFmNmEiLCJib2R5Ijp7Im1lc3NhZ2UiOiJtZXNhZ2UiLCJzY29wZSI6W3siaWQiOjEsImNpcmN1aXRJZCI6ImNyZWRlbnRpYWxBdG9taWNRdWVyeVYzLWJldGEuMSIsInByb29mIjp7InBpX2EiOlsiMTk1NzA0Mjk4MzUyMTkzOTc3Nzc3OTM1ODYxMzUxMjk0MDUzODc0ODM3MTAwMTUwMzU5OTc5NjUwNDA3OTk5MTU4NTE1MTg0NTYyNiIsIjU5ODA0NjcwODg0OTE1MzA3MDA5ODA3NDE4NjcxODY3NzA5MzYxNTQxODY0NTkyODUwOTQ1NzU5MDc2OTMzMDMwNDgwMzY5NjM2ODkiLCIxIl0sInBpX2IiOltbIjU3NDI2NzExNDY3ODMwNDk4OTY3ODk0NTc2Mzc1MDYxNjg2NTAzMTMxMTc2MDg4OTIyODc3NjIwOTE4MjYwODYxNzk3NDY4NjA0NjkiLCI3ODY3OTgwMDAyMjE0Mjk5ODgzNDAxNTUzMDAxODE0ODM3MTE0NzIzNTM2NzkwNDcyODM1NTEwMzY1OTc1NTM0Mjc0MTkwNjc3NDkwIl0sWyI2NDA5OTE5NDg1NzgzOTgyMzM1NTg1MTc5NzI3MDQyNDQyMTk0MzIxNzA3MzgzNDk5ODcyNjk5MTg5NzQwMzE4NDQ1MDUxMzkwOTYxIiwiMTM2OTk4MDA2ODc3OTUzNzIyNjI0NDE5MDEyNzUwNDQwODIzNzI5OTUyMDk4ODgwMTU2MDkzNzczMzIxNDY4MjA5NDc4MjYxMzExNyJdLFsiMSIsIjAiXV0sInBpX2MiOlsiNTcxMTEyMTQ5NDgyMDA2NjQ2MzIwMDg5Mzk4NTM4NjY1MTU1NTk4MDA0NTY4NDU5NjA2MTE1OTY0MzEzODE2MjExMzc4NjQyNzgwMiIsIjQwOTU4MTgzNjQ4MDgzNjc1NzkyNDIyNzU5NzQyNDk1ODQxNTIwODkyNTM5OTU4NjE5MjE0MDY2Njg1MjIxOTU4OTgxNTg4NTMwOTAiLCIxIl0sInByb3RvY29sIjoiZ3JvdGgxNiIsImN1cnZlIjoiYm4xMjgifSwicHViX3NpZ25hbHMiOlsiMCIsIjIxNTY4MjI1NDY5ODg5NDU4MzA1OTE0ODQxNDkwMTc1MjgwMDkzNTU1MDE1MDcxMzI5Nzg3Mzc1NjQxNDMxMjYyNTA5MjA4MDY1IiwiNDQ4NzM4NjMzMjQ3OTQ4OTE1ODAwMzU5Nzg0NDk5MDQ4Nzk4NDkyNTQ3MTgxMzkwNzQ2MjQ4MzkwNzA1NDQyNTc1OTU2NDE3NTM0MSIsIjAiLCIwIiwiMCIsIjEiLCIxIiwiMjUxOTE2NDE2MzQ4NTM4NzUyMDcwMTgzODEyOTA0MDkzMTc4NjAxNTE1NTEzMzYxMzM1OTcyNjcwNjE3MTU2NDM2MDMwOTYwNjUiLCIxIiwiNDQ4NzM4NjMzMjQ3OTQ4OTE1ODAwMzU5Nzg0NDk5MDQ4Nzk4NDkyNTQ3MTgxMzkwNzQ2MjQ4MzkwNzA1NDQyNTc1OTU2NDE3NTM0MSIsIjE3MDkyMjU0NjEiLCIxOTgyODU3MjY1MTA2ODgyMDAzMzUyMDcyNzM4MzYxMjMzMzg2OTkiLCIwIiwiMyIsIjEiLCI5OSIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjEiLCIyNTE5MTY0MTYzNDg1Mzg3NTIwNzAxODM4MTI5MDQwOTMxNzg2MDE1MTU1MTMzNjEzMzU5NzI2NzA2MTcxNTY0MzYwMzA5NjA2NSIsIjAiXX0seyJpZCI6MiwiY2lyY3VpdElkIjoibGlua2VkTXVsdGlRdWVyeTEwLWJldGEuMSIsInByb29mIjp7InBpX2EiOlsiMTAwMDg3NjI5ODcxMzUyNTI3NDgzNDMzMzY4NTI0NDA4MjE5OTkyOTIyMDAxOTQ1ODY2MDk0MzExMjMxNTg4Nzc5MjQ4Mjk0NDI2MTkiLCI2NDMxMjA4ODM2MDYzNzAyNDMxNjUzMTUyNjc3Mjg5MjU3MjQzODM0NDExMzE1NTU2MzI0OTY4NzU4MTA5NjY1NzExODAxNDI4MzYiLCIxIl0sInBpX2IiOltbIjIwMzI1MjAyNDI3ODg4MjE4MzA1MDQyMDAxMDUxNjExNjkxNzkxMDEzNTQ1OTQ5NTg5ODY0MTQwNDM3ODc1NDU4NjI4NDM3NTk5NzcwIiwiODcxNzYwMDE0NDUzMzk5MzM2MTE3MTY1ODE5MjI4ODc1NjQ0NjgxMTEwODIyMTI5MzE2MTYzNjcxNzIzNzkwOTk5MzkyNjcxMDMxOCJdLFsiMTQ5ODE2MTk5NTgxOTExNTc1ODEyMjcxMTQwMDA4NzIwNTQ0NTczNzEzNzMzOTM1NjU5OTczMDIxNjYzMDI4NzYxNDc1MDMyODQzMzgiLCIxNjU1MzYzNjU4NzcyODQ4NzI2MzU5MjU4MDE1NDEyMzE5NDI5MjQ3MjM1MDg0NTEwNzI2ODA0MTE5MTEyMjA1NzQ4MzAzMDAzMjUxNyJdLFsiMSIsIjAiXV0sInBpX2MiOlsiMTYwNzIxMjY1ODk5NzYxMDc4NTcyMzYxNDI4MjE2MTMxOTM1MTgyMDk3NDk0MDE1MjEzOTgwNjUwMTk0MjU3NDgwOTIxOTI2MTQ5NTkiLCIzMDM5MDY2ODIyOTY4Njk1MDIzNDIyNzY5ODgxMjM3MTY5NTg5OTA1MDA3OTg2OTU0NTYzNTc1MzExMDc4MzU5MjQ5MzkyNTkxNTAiLCIxIl0sInByb3RvY29sIjoiZ3JvdGgxNiIsImN1cnZlIjoiYm4xMjgifSwicHViX3NpZ25hbHMiOlsiMTQ4NDA1OTUzMzQ5ODk1NTA2MTY0NjYwODMxOTcxODAwMDA3ODc2MjE2MjAwODM1MzY4OTA5MjM5MDQyMjgyMzUyMTMzNTY3MjYxNjUiLCIxIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjE1NTc3MTE0Nzk5MDU2OTM5NjMzNTUyODQ1NTMxMDExMDI0NjcyOTM5NDkzNDkyNzY5NjI4Mjg1NjYxMzU5NzExNjU1MjE0NTYxMTYyIiwiMTY5OTg3NjI5NjUzOTY5NDQ3ODI2Njc1NTc3NDExODU4MjgxMzY0Njc3NDc3NjI4MzAwMjgyMTcwMjc5NzM2MTczNzM4NjIzMDE5NTgiLCI5MzAyNTI2MjA4NTA3NzUzNzk5NTAxMTMwMTI4OTA4NDk0NjczNDEyNDQzNjMxNTQxNDI0NDA5NTUxMjA1Mjc3NTI5OTQ5NjYyMzk0IiwiMTQ2MTI1MTgwMDY0OTM5OTgwMzcxNDkyOTk2NDc5NzQyMzc3NzE1NTEwNzAzMTIwOTY4ODI0MDc0NDA2NTEwNTI3NTIyNTkwMzg0MDMiLCIxNDYxMjUxODAwNjQ5Mzk5ODAzNzE0OTI5OTY0Nzk3NDIzNzc3MTU1MTA3MDMxMjA5Njg4MjQwNzQ0MDY1MTA1Mjc1MjI1OTAzODQwMyIsIjE0NjEyNTE4MDA2NDkzOTk4MDM3MTQ5Mjk5NjQ3OTc0MjM3NzcxNTUxMDcwMzEyMDk2ODgyNDA3NDQwNjUxMDUyNzUyMjU5MDM4NDAzIiwiMTQ2MTI1MTgwMDY0OTM5OTgwMzcxNDkyOTk2NDc5NzQyMzc3NzE1NTEwNzAzMTIwOTY4ODI0MDc0NDA2NTEwNTI3NTIyNTkwMzg0MDMiLCIxNDYxMjUxODAwNjQ5Mzk5ODAzNzE0OTI5OTY0Nzk3NDIzNzc3MTU1MTA3MDMxMjA5Njg4MjQwNzQ0MDY1MTA1Mjc1MjI1OTAzODQwMyIsIjE0NjEyNTE4MDA2NDkzOTk4MDM3MTQ5Mjk5NjQ3OTc0MjM3NzcxNTUxMDcwMzEyMDk2ODgyNDA3NDQwNjUxMDUyNzUyMjU5MDM4NDAzIiwiMTQ2MTI1MTgwMDY0OTM5OTgwMzcxNDkyOTk2NDc5NzQyMzc3NzE1NTEwNzAzMTIwOTY4ODI0MDc0NDA2NTEwNTI3NTIyNTkwMzg0MDMiXX0seyJpZCI6MywiY2lyY3VpdElkIjoiY3JlZGVudGlhbEF0b21pY1F1ZXJ5VjMtYmV0YS4xIiwicHJvb2YiOnsicGlfYSI6WyI0OTE4NDIxOTY4MjIyOTk0ODc1MDY1MTMyOTE5MzU3Nzg4NzE2NTI3NDEwMDIwMDEzMzE0MDc2ODM4MDc1NjAxNzM5ODc2ODM4MTE2IiwiMTA1NzY3MTQ4MDExNDkxNjI1MjY2NjU4ODMxODU5NTQxMzY4MjUyMjgyODI5ODAyMTYzNzM4MDI0OTU3NzY0MTQ2NDg1NDcyNTAzODkiLCIxIl0sInBpX2IiOltbIjExMTA4NTc4MTM4MTk3NjY1NTI1NzM1MTU1OTIwMjUxODAxNzE3ODg4MDk4MTYwNjkzNzY0NjM5NDU0Njc5ODgwOTI4NzIyNzMzODgwIiwiMzk5NzcyMTI0NzE1OTg0NDYxODgxNzI3NzU4NTA1NTE5ODgxMTExMDExNzI0NjY3NjYyMjYyOTg3OTU0MzQwMTc5NTY0NjY2NzAyNyJdLFsiMjA2MzU0NzMxNzIxNDE0NDc3MTEyMjU3ODMxOTY1NzQxNzE1Nzg0OTM3NDI1NzU4NDk0OTM0MTQ1NDcyOTM1Njg0ODcxMjIxMjk5NjMiLCI2OTQ4NDQzMTc5NjE5MDU5Njg5Mzg3NzEwNjQyMDA2NDEyOTAxNjI2Mjc4MzIyMjMyOTY1MzU0MzAwNTQ0MDUzODQ2MjE3NzQzMTEwIl0sWyIxIiwiMCJdXSwicGlfYyI6WyI0NjkxMTkzMjY3OTQyMjk0NDc5MzU3NzUyMDM0NTMyMzM4MDY1NDg5NzEzOTMxMjU2NzUwNTMyNDI5MjkwODQwNzIwNTQzMjg3NjkiLCIxNzg4MTM5MDY2MjcxNTAzMzgyODM5Nzk4NDQzMjY0NTU5ODI1OTA1OTgwMzMzMjIyNDk4OTczNTk2OTczNzY3MjY4Nzk2NTQ2MjUiLCIxIl0sInByb3RvY29sIjoiZ3JvdGgxNiIsImN1cnZlIjoiYm4xMjgifSwicHViX3NpZ25hbHMiOlsiMSIsIjIxNTY4MjI1NDY5ODg5NDU4MzA1OTE0ODQxNDkwMTc1MjgwMDkzNTU1MDE1MDcxMzI5Nzg3Mzc1NjQxNDMxMjYyNTA5MjA4MDY1IiwiNDQ4NzM4NjMzMjQ3OTQ4OTE1ODAwMzU5Nzg0NDk5MDQ4Nzk4NDkyNTQ3MTgxMzkwNzQ2MjQ4MzkwNzA1NDQyNTc1OTU2NDE3NTM0MSIsIjE0ODQwNTk1MzM0OTg5NTUwNjE2NDY2MDgzMTk3MTgwMDAwNzg3NjIxNjIwMDgzNTM2ODkwOTIzOTA0MjI4MjM1MjEzMzU2NzI2MTY1IiwiMjEwNTE4MTY0Mzc3MTE5OTgwMTcyNDkwNTA0NDQyNDQ3Mjc4MDY4NjEwMjU3MDc4MDQ4OTc4MTM5NTE4NDIyODY2OTAzODI0NzI5MjciLCIwIiwiMSIsIjMiLCIyNTE5MTY0MTYzNDg1Mzg3NTIwNzAxODM4MTI5MDQwOTMxNzg2MDE1MTU1MTMzNjEzMzU5NzI2NzA2MTcxNTY0MzYwMzA5NjA2NSIsIjEiLCI0NDg3Mzg2MzMyNDc5NDg5MTU4MDAzNTk3ODQ0OTkwNDg3OTg0OTI1NDcxODEzOTA3NDYyNDgzOTA3MDU0NDI1NzU5NTY0MTc1MzQxIiwiMTcwOTIyNTQ3NyIsIjIxOTU3ODYxNzA2NDU0MDAxNjIzNDE2MTY0MDM3NTc1NTg2NTQxMiIsIjEyOTYzNTE3NTgyNjkwNjExNzMzMTcxMDUwNDE5NjgwNjcwNzc0NTE5MTQzODYwODYyMjI5MzE1MTYxOTkxOTQ5NTk4Njk0NjM4ODIiLCIwIiwiMSIsIjE3MDIyNTI4MDAwMDAwMDAwMDAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIxIiwiMjUxOTE2NDE2MzQ4NTM4NzUyMDcwMTgzODEyOTA0MDkzMTc4NjAxNTE1NTEzMzYxMzM1OTcyNjcwNjE3MTU2NDM2MDMwOTYwNjUiLCIxMjM0NSJdfV19LCJmcm9tIjoiZGlkOmlkZW4zOnBvbHlnb246bXVtYmFpOnd1dzV0eWRaN0FBZDNlZndFcVBwcm5xamlOSFIyNGpxcnVTUEttVjFWIiwidG8iOiJkaWQ6aWRlbjM6cG9seWdvbjptdW1iYWk6d3pva3ZaNmtNb29jS0p1U2JmdGRaeFRENnF2YXlHcEpiM200RlZYdGgifQ.eyJwcm9vZiI6eyJwaV9hIjpbIjE2NzU3ODM5MDEyMjc2ODEwNzY4MzUzOTEwMzM5MDkzNjMyMDMyNTE5NjcyMjIwODc3OTUwNDYxNjUyNjI4ODExNDIzODQ1MzAzMTEzIiwiMTA2MTUzNzQ3ODE5NjY0MzAxMTI5Mjk3MTk1NjY4MzU2Mjc2NjE4NDc3ODc2NDk0NjU3MDIyMDUwNDIxMjUxOTU4OTU5NTYzMDExNCIsIjEiXSwicGlfYiI6W1siMTg2Njk4MjAwNDAzNzc1MTM3ODIwMDgwMjA5ODc5NTg5MjU5NTMwNjYyNTA1MTU5MzIzNzMwNjg4MzQ3MDg2MzQxMDc5MTY4NDgxNjIiLCIxMTE1OTM1Mzc2MjY2ODA0MjgzODU0NTk4NTMyNTUwNzAyMzM0NzQwODYyNDMxMzc0NTkwNjQ3ODYyNTUzNTg2ODA1NDU4MDE5NjQxMCJdLFsiNjg2NTkwOTkzNjMyMjEwNTMzNjY2NDE0NTYwNjgxNzY3ODEzOTc2MTAyMTI2Mzc0NTY5OTc5NjEyNjYwNTEwNjkxNjE2NDE4ODU2NiIsIjYwMDQ3MzAxMjU3NjgyODUxMTA0Nzg5MzIzNjU2MDU0NDcwODE2ODEzNjAwNjg0MzQyMTIyOTU2NTc5MzA0NTQ5MTkyNzU4MTYwNjQiXSxbIjEiLCIwIl1dLCJwaV9jIjpbIjE5NDk2ODkzMzg1NTkwMjYzMTgyNzc1NDkwMDc2Mjg3ODM1MTA4ODkwMDk5Mjc1MDEzMjIzNTc5MDAzMTU4NTgzNzU0MjEzMjQzNzI1IiwiMTU5MjMxNjQ1OTM4MDQ0NTQ1NjEwOTcyNDIxMDU4MzUxMTEzNTQ2NTM5NDUzOTcyNzU1MjkwMDUzNTgwNzAxODIwNzEwMTYwMDA5MDkiLCIxIl0sInByb3RvY29sIjoiZ3JvdGgxNiIsImN1cnZlIjoiYm4xMjgifSwicHViX3NpZ25hbHMiOlsiMjE1NjgyMjU0Njk4ODk0NTgzMDU5MTQ4NDE0OTAxNzUyODAwOTM1NTUwMTUwNzEzMjk3ODczNzU2NDE0MzEyNjI1MDkyMDgwNjUiLCIxODQ3MTgwNTcyMjUyNjQ0MjAxMzgyODkwOTgyOTc3MzIxMDc2MzA3Mjg1NzgyNDIwODc0MjM5OTYyNDk0NTI2Mzc5NTM5ODkwMDc5NyIsIjAiXX0"
	returnMsg, err := authInstance.FullVerify(context.Background(), tokenString, request, pubsignals.WithAcceptedProofGenerationDelay(proofGenerationDelay))
	require.Nil(t, err)
	require.NotNil(t, returnMsg)
	schemaLoader.assert(t)
}

func TestVerifier_FullVerify_ExpiredMessage(t *testing.T) {
	verifierID := "did:polygonid:polygon:mumbai:2qJ689kpoJxcSzB5sAFJtPsSBSrHF5dq722BHMqURL"
	callbackURL := "https://test.com/callback"
	reason := "age verification"
	expiredTime := time.Now().Add(-time.Hour)
	request := CreateAuthorizationRequestWithMessage(reason, "", verifierID, callbackURL, WithExpiresTime(&expiredTime))
	request.ID = "28494007-9c49-4f1a-9694-7700c08865bf"
	request.ThreadID = "ee92ab12-2671-457e-aa5e-8158c205a985" // because it's used in the response
	token := `eyJhbGciOiJncm90aDE2IiwiY2lyY3VpdElkIjoiYXV0aFYyIiwiY3JpdCI6WyJjaXJjdWl0SWQiXSwidHlwIjoiYXBwbGljYXRpb24vaWRlbjMtemtwLWpzb24ifQ.eyJpZCI6IjljMGY5NjIzLWM1NmMtNDEwNC04ODk2LWVjMjgyYTNiMmExNyIsInR5cCI6ImFwcGxpY2F0aW9uL2lkZW4zY29tbS1wbGFpbi1qc29uIiwidHlwZSI6Imh0dHBzOi8vaWRlbjMtY29tbXVuaWNhdGlvbi5pby9hdXRob3JpemF0aW9uLzEuMC9yZXNwb25zZSIsInRoaWQiOiI3ZjM4YTE5My0wOTE4LTRhNDgtOWZhYy0zNmFkZmRiOGI1NDIiLCJmcm9tIjoiZGlkOnBvbHlnb25pZDpwb2x5Z29uOm11bWJhaToycVBETFhEYVUxeGExRVJUYjFYS0JmUENCM28yd0E0NnE0OW5laVhXd1kiLCJ0byI6ImRpZDpwb2x5Z29uaWQ6cG9seWdvbjptdW1iYWk6MnFKNjg5a3BvSnhjU3pCNXNBRkp0UHNTQlNySEY1ZHE3MjJCSE1xVVJMIiwiYm9keSI6eyJkaWRfZG9jIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy9ucy9kaWQvdjEiXSwiaWQiOiJkaWQ6cG9seWdvbmlkOnBvbHlnb246bXVtYmFpOjJxUERMWERhVTF4YTFFUlRiMVhLQmZQQ0IzbzJ3QTQ2cTQ5bmVpWFd3WSIsInNlcnZpY2UiOlt7ImlkIjoiZGlkOnBvbHlnb25pZDpwb2x5Z29uOm11bWJhaToycVBETFhEYVUxeGExRVJUYjFYS0JmUENCM28yd0E0NnE0OW5laVhXd1kjcHVzaCIsInR5cGUiOiJwdXNoLW5vdGlmaWNhdGlvbiIsInNlcnZpY2VFbmRwb2ludCI6Imh0dHBzOi8vcHVzaC1zdGFnaW5nLnBvbHlnb25pZC5jb20vYXBpL3YxIiwibWV0YWRhdGEiOnsiZGV2aWNlcyI6W3siY2lwaGVydGV4dCI6InhZK3RHWHUrOWlHMHZ6dFpMTTlKN25PcDNRbE1Uci85TmI3Qjl5Q0prbDlxcUpiZ1AvMExOL1VmTkxxQUk4RWZIcFhJVlVlTmVVUmNCNm82bWVMVlpJK2VvMlhvcDM2SE1iK2JyQnJTTjRqVHZWVkRDQXVXSkI2akV5Q3ZNRzlMaXp6blBsS3VQSE15dEdCVnZnV0laRFZBeVdZbTFyMk9PUzc4OU5DZm41MnNjV0VRVW5VRWdnTmpyWjlLdFpmb09RMlBDbUpqRXpDejg0ZUc3RGM2bEFvbi8ycTJJNVlLQk12RkhnT3c4N25wb0owczVrQ1RVVENjeVRlQmg2VXpLQk5aNElibndvR3ZYcG9FelBVZXZRdjRGbXVTaExYYVF3Vk9nalRBUXR0T2g2SjZhcmE4UHNndVFGQ3dNUTlxV2JjTjZYdXlScjk4TVlqbGxpL0VEN09TZzBsWVU5cUdLa1RaL2ZZN2VWZkYyeFFhOWZXK01WVzlxM2NJMjJzbkRwV28xY1ZYNWt1TWhpbmFsajZXV1Q0OTAvblNXak1rZ3JkL25CdXNiMHR4eG1jWDU3QUowcVlyMkNsK0pQb1FhcExiOEFTT3dGYU5kRDRZV3pKWXRXVmlDbktMZ3dQNDFHaGl5NVNWZE1vbU1sUy9kSGo2TVZPMjNyOVRiTDFrRy8rdkFIZWF0YkdvZ3p1OWd3SzlJckF3WS95THhMYVpQcHZzdlJLWjVBa2E1b1pkbmRNNkdLUkM0OVhoVXloQnNlY0N2Z1hNeGZGNVBnWGhROVFTb1drMzFXSWRiWG5vbmU2YmVNQkpLUVYzemg2MmpoZUFuV3czZW16dndKajRUUHU4WTJQZ2lDL3FaZXhlUVlKdFNkelJXZUFjK2N5a2ZwTXA0SmdrV2hBPSIsImFsZyI6IlJTQS1PQUVQLTUxMiJ9XX19XX0sIm1lc3NhZ2UiOm51bGwsInNjb3BlIjpbeyJpZCI6MjMsImNpcmN1aXRJZCI6ImNyZWRlbnRpYWxBdG9taWNRdWVyeU1UUFYyIiwicHJvb2YiOnsicGlfYSI6WyIyNjEwNjg1Nzc1MTY0Mzc0MDE2MTM5NDQwNTM4NzMxODI0NTgzNjQyODg0MTQxMzA5MTQwNDgzNDU0ODMzNzcyMjYxNDQ2NTI2NTEiLCIxNDE5MTI2MDA3MTY5NTk4MDAxMTY3OTUwMTgwODQ1MzIyMjI2NzUyMDcyMTc2Nzc1Nzc1OTE1MDEwMTk3NDM4MjA1MzE2MTY3NDYxMSIsIjEiXSwicGlfYiI6W1siNzY3MDg0Nzg0NDAxNTExNjk1NzUyNjE4MzcyODE5Njk3Nzk1NzMxMjYyNzMwNzc5NzkxOTU1NDEzNDY4NDkwMTQwMTQzNjAyMTk3NyIsIjE0OTU3ODQ1NDcyNjMwMDE3MDk1ODIxODMzMjIyNTgwMTk0MDYxMjY2MTg2ODUxNjM0MDUzODk3NzY4NzM4MjUzNjYzMjUzNjUwODM1Il0sWyIxNzgzNTY0MjQ1ODQ4NDYyODYyNzU1NjMyOTg3NjkxOTA3NzMzMzkxMjAxMTIzNTMwODc1ODgzMjE3Mjg4MDAxMjgxMzM5NzAyMjEwNCIsIjE4MTAwODYxMTMwMTQ5Njc4MTUzMTMzMDI1MDMxNzA5ODk3MTIwMDk3MDk4NTkxMjk4ODE3MzY3NDkxOTIwNTUzMDM3MDExNjUwMjI4Il0sWyIxIiwiMCJdXSwicGlfYyI6WyI2MjE3ODY1OTQ5Mjk5OTkwNjQyODMyNTIzMjU2ODYzMDQ4OTMyMjEwNTQ2MDQ5MjAzMTg5MTEzMzYyODUxNDc2OTY2ODI0MTYyMTkxIiwiMTkwMTY5NDkyMjUyNzc3NTU2OTAwMTk2NDczODU4NTU5MzY5Njk5Mjg5OTQyMTA5MDU5OTI2MjgzMDE5Njc4ODM4MDM2NzA0MzY1MTAiLCIxIl0sInByb3RvY29sIjoiZ3JvdGgxNiIsImN1cnZlIjoiYm4xMjgifSwicHViX3NpZ25hbHMiOlsiMSIsIjI3MTUyNjc2OTg3MTI4NTQyMDY2ODA4NTkxOTk4NTczMDAwMzcwNDM2NDY0NzIyNTE5NTEzMzQ4ODkxMDQ5NjQ0ODEzNzE4MDE4IiwiMjMiLCIyNzc1Mjc2NjgyMzM3MTQ3MTQwODI0ODIyNTcwODY4MTMxMzc2NDg2NjIzMTY1NTE4NzM2NjA3MTg4MTA3MDkxODk4NDQ3MTA0MiIsIjIxNTQ1NzY4ODgzNTA5NjU3MzQwMjA5MTcxNTQ5NDQxMDA1NjAzMzA2MDEyNTEzOTMyMjIxMzcxNTk5NTAxNDk4NTM0ODA3NzE5Njg5IiwiMSIsIjIxNTQ1NzY4ODgzNTA5NjU3MzQwMjA5MTcxNTQ5NDQxMDA1NjAzMzA2MDEyNTEzOTMyMjIxMzcxNTk5NTAxNDk4NTM0ODA3NzE5Njg5IiwiMTY3OTMyMzAzOCIsIjMzNjYxNTQyMzkwMDkxOTQ2NDE5MzA3NTU5Mjg1MDQ4MzcwNDYwMCIsIjAiLCIxNzAwMjQzNzExOTQzNDYxODc4MzU0NTY5NDYzMzAzODUzNzM4MDcyNjMzOTk5NDI0NDY4NDM0ODkxMzg0NDkyMzQyMjQ3MDgwNjg0NCIsIjAiLCI1IiwiODQwIiwiMTIwIiwiMzQwIiwiNTA5IiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIl19XX19.eyJwcm9vZiI6eyJwaV9hIjpbIjcwMjI2MTEzODk5MzY1MDEzNDI2NTkwMjQ2Njk0NTczNTA3OTUwMTU5ODkzOTI1NzAzMDMwODQ4MzcyMTQ4MDc1MzYyNDg4NTE5MzYiLCIxMzg1OTcwODc3NTU0Mzk0Mjk3MTYxNTcxNTA1MTczNjM4MTc4NTEzODkzMjQ3ODc1Mzg3MjU5MTU0NDQxODk1ODkwOTU2MDQyOTU3NCIsIjEiXSwicGlfYiI6W1siMTE1MzQ5NjMxNDgwODQ0OTk0NDg5MDc3NzQxMTMxNjg1OTEyNDYyMjQ4OTg0MTU4ODAwMzY5NTA1MDYyMjU0ODkyMDA1NTc2NTA2NjUiLCIxNDA3MjA4Mjk1MTQ0Njc5NDk5MDk4NDcwNTE3ODA1OTY2NjI4NzM1NTEwNjc5MzUwMTg5MTE2ODgwNjE2NjUwMTUxMDkzMDY0MzQ0MSJdLFsiNDY3ODgyNDc3ODQ5ODA0NzE2OTEzNTk2NTg3MTYwNDgzNjkwMTQ1NjI5MDQ0NjQ0NjUzMzEyNzUwOTU4Mzg5MDU5MDkzNTY5ODQxNCIsIjEyODE5NzMwNTMyMDg0MTM4NDI0ODQ0MjExNDg4NjcxMTUyNDgwOTU1MzQ0MTA2NzU4NTE3NDEzODAxOTIzNTM3OTU3MzYzOTgwMjA0Il0sWyIxIiwiMCJdXSwicGlfYyI6WyIxNTUyMDYzNjk4OTY2MTg3NzExNDUwNjkwNDgxMDQxMzExNDI4NzQ5ODE1OTk2NDA5OTU2MTY5ODUyNjc4MzUwMDE1NjU1MjQzMDAwNCIsIjEyNjkyNzA3NDA3MTczMDg0OTM5NzQ1ODU5NzE0ODMxNDYyMDQ1ODg5NDA4NTk4NTI3MjU0ODA3NzkwNDk0NDY2Mjc5Njg3ODU5MjQ3IiwiMSJdLCJwcm90b2NvbCI6Imdyb3RoMTYiLCJjdXJ2ZSI6ImJuMTI4In0sInB1Yl9zaWduYWxzIjpbIjI3MTUyNjc2OTg3MTI4NTQyMDY2ODA4NTkxOTk4NTczMDAwMzcwNDM2NDY0NzIyNTE5NTEzMzQ4ODkxMDQ5NjQ0ODEzNzE4MDE4IiwiMTIxODQ5NzQwNzE0Mjc3NjgzNTIwMjcwMDM4NzgzMTkzMzgyNDkzODM4NDYxNjQ3MzAyMDQ1MDUzMjY5NTM1NTA2NDczOTExNzg4MDAiLCI4NzU2MDYwMjA1MDg2ODAzMzM1MjUyMzE5NzQ4NzQ4MzU0NzYxOTYxODE0MDEyNzI1NDk5ODczMzgyOTg4MDU2NDE4NjgwNjI4NjE5Il19`
	authInstance, err := NewVerifier(verificationKeyloader, stateResolvers)
	require.NoError(t, err)
	_, err = authInstance.FullVerify(context.Background(), token, request, pubsignals.WithAcceptedProofGenerationDelay(proofGenerationDelay), pubsignals.WithAllowExpiredMessages(false))
	require.Error(t, err, errors.New("Authorization request message is expired"))
}

func TestVerifier_FullVerify_ExpiredMessageWithAllowExpired(t *testing.T) {
	verifierID := "did:polygonid:polygon:mumbai:2qJ689kpoJxcSzB5sAFJtPsSBSrHF5dq722BHMqURL"
	callbackURL := "https://test.com/callback"
	reason := "age verification"
	expiredTime := time.Now().Add(-time.Hour)
	request := CreateAuthorizationRequestWithMessage(reason, "", verifierID, callbackURL, WithExpiresTime(&expiredTime))
	request.ID = "28494007-9c49-4f1a-9694-7700c08865bf"
	request.ThreadID = "ee92ab12-2671-457e-aa5e-8158c205a985" // because it's used in the response
	token := `eyJhbGciOiJncm90aDE2IiwiY2lyY3VpdElkIjoiYXV0aFYyIiwiY3JpdCI6WyJjaXJjdWl0SWQiXSwidHlwIjoiYXBwbGljYXRpb24vaWRlbjMtemtwLWpzb24ifQ.eyJpZCI6IjljMGY5NjIzLWM1NmMtNDEwNC04ODk2LWVjMjgyYTNiMmExNyIsInR5cCI6ImFwcGxpY2F0aW9uL2lkZW4zY29tbS1wbGFpbi1qc29uIiwidHlwZSI6Imh0dHBzOi8vaWRlbjMtY29tbXVuaWNhdGlvbi5pby9hdXRob3JpemF0aW9uLzEuMC9yZXNwb25zZSIsInRoaWQiOiI3ZjM4YTE5My0wOTE4LTRhNDgtOWZhYy0zNmFkZmRiOGI1NDIiLCJmcm9tIjoiZGlkOnBvbHlnb25pZDpwb2x5Z29uOm11bWJhaToycVBETFhEYVUxeGExRVJUYjFYS0JmUENCM28yd0E0NnE0OW5laVhXd1kiLCJ0byI6ImRpZDpwb2x5Z29uaWQ6cG9seWdvbjptdW1iYWk6MnFKNjg5a3BvSnhjU3pCNXNBRkp0UHNTQlNySEY1ZHE3MjJCSE1xVVJMIiwiYm9keSI6eyJkaWRfZG9jIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy9ucy9kaWQvdjEiXSwiaWQiOiJkaWQ6cG9seWdvbmlkOnBvbHlnb246bXVtYmFpOjJxUERMWERhVTF4YTFFUlRiMVhLQmZQQ0IzbzJ3QTQ2cTQ5bmVpWFd3WSIsInNlcnZpY2UiOlt7ImlkIjoiZGlkOnBvbHlnb25pZDpwb2x5Z29uOm11bWJhaToycVBETFhEYVUxeGExRVJUYjFYS0JmUENCM28yd0E0NnE0OW5laVhXd1kjcHVzaCIsInR5cGUiOiJwdXNoLW5vdGlmaWNhdGlvbiIsInNlcnZpY2VFbmRwb2ludCI6Imh0dHBzOi8vcHVzaC1zdGFnaW5nLnBvbHlnb25pZC5jb20vYXBpL3YxIiwibWV0YWRhdGEiOnsiZGV2aWNlcyI6W3siY2lwaGVydGV4dCI6InhZK3RHWHUrOWlHMHZ6dFpMTTlKN25PcDNRbE1Uci85TmI3Qjl5Q0prbDlxcUpiZ1AvMExOL1VmTkxxQUk4RWZIcFhJVlVlTmVVUmNCNm82bWVMVlpJK2VvMlhvcDM2SE1iK2JyQnJTTjRqVHZWVkRDQXVXSkI2akV5Q3ZNRzlMaXp6blBsS3VQSE15dEdCVnZnV0laRFZBeVdZbTFyMk9PUzc4OU5DZm41MnNjV0VRVW5VRWdnTmpyWjlLdFpmb09RMlBDbUpqRXpDejg0ZUc3RGM2bEFvbi8ycTJJNVlLQk12RkhnT3c4N25wb0owczVrQ1RVVENjeVRlQmg2VXpLQk5aNElibndvR3ZYcG9FelBVZXZRdjRGbXVTaExYYVF3Vk9nalRBUXR0T2g2SjZhcmE4UHNndVFGQ3dNUTlxV2JjTjZYdXlScjk4TVlqbGxpL0VEN09TZzBsWVU5cUdLa1RaL2ZZN2VWZkYyeFFhOWZXK01WVzlxM2NJMjJzbkRwV28xY1ZYNWt1TWhpbmFsajZXV1Q0OTAvblNXak1rZ3JkL25CdXNiMHR4eG1jWDU3QUowcVlyMkNsK0pQb1FhcExiOEFTT3dGYU5kRDRZV3pKWXRXVmlDbktMZ3dQNDFHaGl5NVNWZE1vbU1sUy9kSGo2TVZPMjNyOVRiTDFrRy8rdkFIZWF0YkdvZ3p1OWd3SzlJckF3WS95THhMYVpQcHZzdlJLWjVBa2E1b1pkbmRNNkdLUkM0OVhoVXloQnNlY0N2Z1hNeGZGNVBnWGhROVFTb1drMzFXSWRiWG5vbmU2YmVNQkpLUVYzemg2MmpoZUFuV3czZW16dndKajRUUHU4WTJQZ2lDL3FaZXhlUVlKdFNkelJXZUFjK2N5a2ZwTXA0SmdrV2hBPSIsImFsZyI6IlJTQS1PQUVQLTUxMiJ9XX19XX0sIm1lc3NhZ2UiOm51bGwsInNjb3BlIjpbeyJpZCI6MjMsImNpcmN1aXRJZCI6ImNyZWRlbnRpYWxBdG9taWNRdWVyeU1UUFYyIiwicHJvb2YiOnsicGlfYSI6WyIyNjEwNjg1Nzc1MTY0Mzc0MDE2MTM5NDQwNTM4NzMxODI0NTgzNjQyODg0MTQxMzA5MTQwNDgzNDU0ODMzNzcyMjYxNDQ2NTI2NTEiLCIxNDE5MTI2MDA3MTY5NTk4MDAxMTY3OTUwMTgwODQ1MzIyMjI2NzUyMDcyMTc2Nzc1Nzc1OTE1MDEwMTk3NDM4MjA1MzE2MTY3NDYxMSIsIjEiXSwicGlfYiI6W1siNzY3MDg0Nzg0NDAxNTExNjk1NzUyNjE4MzcyODE5Njk3Nzk1NzMxMjYyNzMwNzc5NzkxOTU1NDEzNDY4NDkwMTQwMTQzNjAyMTk3NyIsIjE0OTU3ODQ1NDcyNjMwMDE3MDk1ODIxODMzMjIyNTgwMTk0MDYxMjY2MTg2ODUxNjM0MDUzODk3NzY4NzM4MjUzNjYzMjUzNjUwODM1Il0sWyIxNzgzNTY0MjQ1ODQ4NDYyODYyNzU1NjMyOTg3NjkxOTA3NzMzMzkxMjAxMTIzNTMwODc1ODgzMjE3Mjg4MDAxMjgxMzM5NzAyMjEwNCIsIjE4MTAwODYxMTMwMTQ5Njc4MTUzMTMzMDI1MDMxNzA5ODk3MTIwMDk3MDk4NTkxMjk4ODE3MzY3NDkxOTIwNTUzMDM3MDExNjUwMjI4Il0sWyIxIiwiMCJdXSwicGlfYyI6WyI2MjE3ODY1OTQ5Mjk5OTkwNjQyODMyNTIzMjU2ODYzMDQ4OTMyMjEwNTQ2MDQ5MjAzMTg5MTEzMzYyODUxNDc2OTY2ODI0MTYyMTkxIiwiMTkwMTY5NDkyMjUyNzc3NTU2OTAwMTk2NDczODU4NTU5MzY5Njk5Mjg5OTQyMTA5MDU5OTI2MjgzMDE5Njc4ODM4MDM2NzA0MzY1MTAiLCIxIl0sInByb3RvY29sIjoiZ3JvdGgxNiIsImN1cnZlIjoiYm4xMjgifSwicHViX3NpZ25hbHMiOlsiMSIsIjI3MTUyNjc2OTg3MTI4NTQyMDY2ODA4NTkxOTk4NTczMDAwMzcwNDM2NDY0NzIyNTE5NTEzMzQ4ODkxMDQ5NjQ0ODEzNzE4MDE4IiwiMjMiLCIyNzc1Mjc2NjgyMzM3MTQ3MTQwODI0ODIyNTcwODY4MTMxMzc2NDg2NjIzMTY1NTE4NzM2NjA3MTg4MTA3MDkxODk4NDQ3MTA0MiIsIjIxNTQ1NzY4ODgzNTA5NjU3MzQwMjA5MTcxNTQ5NDQxMDA1NjAzMzA2MDEyNTEzOTMyMjIxMzcxNTk5NTAxNDk4NTM0ODA3NzE5Njg5IiwiMSIsIjIxNTQ1NzY4ODgzNTA5NjU3MzQwMjA5MTcxNTQ5NDQxMDA1NjAzMzA2MDEyNTEzOTMyMjIxMzcxNTk5NTAxNDk4NTM0ODA3NzE5Njg5IiwiMTY3OTMyMzAzOCIsIjMzNjYxNTQyMzkwMDkxOTQ2NDE5MzA3NTU5Mjg1MDQ4MzcwNDYwMCIsIjAiLCIxNzAwMjQzNzExOTQzNDYxODc4MzU0NTY5NDYzMzAzODUzNzM4MDcyNjMzOTk5NDI0NDY4NDM0ODkxMzg0NDkyMzQyMjQ3MDgwNjg0NCIsIjAiLCI1IiwiODQwIiwiMTIwIiwiMzQwIiwiNTA5IiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIl19XX19.eyJwcm9vZiI6eyJwaV9hIjpbIjcwMjI2MTEzODk5MzY1MDEzNDI2NTkwMjQ2Njk0NTczNTA3OTUwMTU5ODkzOTI1NzAzMDMwODQ4MzcyMTQ4MDc1MzYyNDg4NTE5MzYiLCIxMzg1OTcwODc3NTU0Mzk0Mjk3MTYxNTcxNTA1MTczNjM4MTc4NTEzODkzMjQ3ODc1Mzg3MjU5MTU0NDQxODk1ODkwOTU2MDQyOTU3NCIsIjEiXSwicGlfYiI6W1siMTE1MzQ5NjMxNDgwODQ0OTk0NDg5MDc3NzQxMTMxNjg1OTEyNDYyMjQ4OTg0MTU4ODAwMzY5NTA1MDYyMjU0ODkyMDA1NTc2NTA2NjUiLCIxNDA3MjA4Mjk1MTQ0Njc5NDk5MDk4NDcwNTE3ODA1OTY2NjI4NzM1NTEwNjc5MzUwMTg5MTE2ODgwNjE2NjUwMTUxMDkzMDY0MzQ0MSJdLFsiNDY3ODgyNDc3ODQ5ODA0NzE2OTEzNTk2NTg3MTYwNDgzNjkwMTQ1NjI5MDQ0NjQ0NjUzMzEyNzUwOTU4Mzg5MDU5MDkzNTY5ODQxNCIsIjEyODE5NzMwNTMyMDg0MTM4NDI0ODQ0MjExNDg4NjcxMTUyNDgwOTU1MzQ0MTA2NzU4NTE3NDEzODAxOTIzNTM3OTU3MzYzOTgwMjA0Il0sWyIxIiwiMCJdXSwicGlfYyI6WyIxNTUyMDYzNjk4OTY2MTg3NzExNDUwNjkwNDgxMDQxMzExNDI4NzQ5ODE1OTk2NDA5OTU2MTY5ODUyNjc4MzUwMDE1NjU1MjQzMDAwNCIsIjEyNjkyNzA3NDA3MTczMDg0OTM5NzQ1ODU5NzE0ODMxNDYyMDQ1ODg5NDA4NTk4NTI3MjU0ODA3NzkwNDk0NDY2Mjc5Njg3ODU5MjQ3IiwiMSJdLCJwcm90b2NvbCI6Imdyb3RoMTYiLCJjdXJ2ZSI6ImJuMTI4In0sInB1Yl9zaWduYWxzIjpbIjI3MTUyNjc2OTg3MTI4NTQyMDY2ODA4NTkxOTk4NTczMDAwMzcwNDM2NDY0NzIyNTE5NTEzMzQ4ODkxMDQ5NjQ0ODEzNzE4MDE4IiwiMTIxODQ5NzQwNzE0Mjc3NjgzNTIwMjcwMDM4NzgzMTkzMzgyNDkzODM4NDYxNjQ3MzAyMDQ1MDUzMjY5NTM1NTA2NDczOTExNzg4MDAiLCI4NzU2MDYwMjA1MDg2ODAzMzM1MjUyMzE5NzQ4NzQ4MzU0NzYxOTYxODE0MDEyNzI1NDk5ODczMzgyOTg4MDU2NDE4NjgwNjI4NjE5Il19`
	authInstance, err := NewVerifier(verificationKeyloader, stateResolvers)
	require.NoError(t, err)
	_, err = authInstance.FullVerify(context.Background(), token, request, pubsignals.WithAcceptedProofGenerationDelay(proofGenerationDelay), pubsignals.WithAllowExpiredMessages(true))
	require.NoError(t, err)
}

func TestVerifier_FullVerify_ResponseTypeNotInAccept(t *testing.T) {
	verifierID := "did:polygonid:polygon:mumbai:2qJ689kpoJxcSzB5sAFJtPsSBSrHF5dq722BHMqURL"
	callbackURL := "https://test.com/callback"
	reason := "age verification"
	acceptProfile := protocol.AcceptProfile{
		AcceptedVersion: protocol.Iden3CommVersion1,
		Env:             packers.MediaTypeSignedMessage,
	}

	accept, err := utils.BuildAcceptProfile([]protocol.AcceptProfile{acceptProfile})
	require.NoError(t, err)
	request := CreateAuthorizationRequestWithMessage(reason, "", verifierID, callbackURL, WithAccept(accept))
	request.ID = "28494007-9c49-4f1a-9694-7700c08865bf"
	request.ThreadID = "ee92ab12-2671-457e-aa5e-8158c205a985"
	token := `eyJhbGciOiJncm90aDE2IiwiY2lyY3VpdElkIjoiYXV0aFYyIiwiY3JpdCI6WyJjaXJjdWl0SWQiXSwidHlwIjoiYXBwbGljYXRpb24vaWRlbjMtemtwLWpzb24ifQ.eyJpZCI6IjljMGY5NjIzLWM1NmMtNDEwNC04ODk2LWVjMjgyYTNiMmExNyIsInR5cCI6ImFwcGxpY2F0aW9uL2lkZW4zY29tbS1wbGFpbi1qc29uIiwidHlwZSI6Imh0dHBzOi8vaWRlbjMtY29tbXVuaWNhdGlvbi5pby9hdXRob3JpemF0aW9uLzEuMC9yZXNwb25zZSIsInRoaWQiOiI3ZjM4YTE5My0wOTE4LTRhNDgtOWZhYy0zNmFkZmRiOGI1NDIiLCJmcm9tIjoiZGlkOnBvbHlnb25pZDpwb2x5Z29uOm11bWJhaToycVBETFhEYVUxeGExRVJUYjFYS0JmUENCM28yd0E0NnE0OW5laVhXd1kiLCJ0byI6ImRpZDpwb2x5Z29uaWQ6cG9seWdvbjptdW1iYWk6MnFKNjg5a3BvSnhjU3pCNXNBRkp0UHNTQlNySEY1ZHE3MjJCSE1xVVJMIiwiYm9keSI6eyJkaWRfZG9jIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy9ucy9kaWQvdjEiXSwiaWQiOiJkaWQ6cG9seWdvbmlkOnBvbHlnb246bXVtYmFpOjJxUERMWERhVTF4YTFFUlRiMVhLQmZQQ0IzbzJ3QTQ2cTQ5bmVpWFd3WSIsInNlcnZpY2UiOlt7ImlkIjoiZGlkOnBvbHlnb25pZDpwb2x5Z29uOm11bWJhaToycVBETFhEYVUxeGExRVJUYjFYS0JmUENCM28yd0E0NnE0OW5laVhXd1kjcHVzaCIsInR5cGUiOiJwdXNoLW5vdGlmaWNhdGlvbiIsInNlcnZpY2VFbmRwb2ludCI6Imh0dHBzOi8vcHVzaC1zdGFnaW5nLnBvbHlnb25pZC5jb20vYXBpL3YxIiwibWV0YWRhdGEiOnsiZGV2aWNlcyI6W3siY2lwaGVydGV4dCI6InhZK3RHWHUrOWlHMHZ6dFpMTTlKN25PcDNRbE1Uci85TmI3Qjl5Q0prbDlxcUpiZ1AvMExOL1VmTkxxQUk4RWZIcFhJVlVlTmVVUmNCNm82bWVMVlpJK2VvMlhvcDM2SE1iK2JyQnJTTjRqVHZWVkRDQXVXSkI2akV5Q3ZNRzlMaXp6blBsS3VQSE15dEdCVnZnV0laRFZBeVdZbTFyMk9PUzc4OU5DZm41MnNjV0VRVW5VRWdnTmpyWjlLdFpmb09RMlBDbUpqRXpDejg0ZUc3RGM2bEFvbi8ycTJJNVlLQk12RkhnT3c4N25wb0owczVrQ1RVVENjeVRlQmg2VXpLQk5aNElibndvR3ZYcG9FelBVZXZRdjRGbXVTaExYYVF3Vk9nalRBUXR0T2g2SjZhcmE4UHNndVFGQ3dNUTlxV2JjTjZYdXlScjk4TVlqbGxpL0VEN09TZzBsWVU5cUdLa1RaL2ZZN2VWZkYyeFFhOWZXK01WVzlxM2NJMjJzbkRwV28xY1ZYNWt1TWhpbmFsajZXV1Q0OTAvblNXak1rZ3JkL25CdXNiMHR4eG1jWDU3QUowcVlyMkNsK0pQb1FhcExiOEFTT3dGYU5kRDRZV3pKWXRXVmlDbktMZ3dQNDFHaGl5NVNWZE1vbU1sUy9kSGo2TVZPMjNyOVRiTDFrRy8rdkFIZWF0YkdvZ3p1OWd3SzlJckF3WS95THhMYVpQcHZzdlJLWjVBa2E1b1pkbmRNNkdLUkM0OVhoVXloQnNlY0N2Z1hNeGZGNVBnWGhROVFTb1drMzFXSWRiWG5vbmU2YmVNQkpLUVYzemg2MmpoZUFuV3czZW16dndKajRUUHU4WTJQZ2lDL3FaZXhlUVlKdFNkelJXZUFjK2N5a2ZwTXA0SmdrV2hBPSIsImFsZyI6IlJTQS1PQUVQLTUxMiJ9XX19XX0sIm1lc3NhZ2UiOm51bGwsInNjb3BlIjpbeyJpZCI6MjMsImNpcmN1aXRJZCI6ImNyZWRlbnRpYWxBdG9taWNRdWVyeU1UUFYyIiwicHJvb2YiOnsicGlfYSI6WyIyNjEwNjg1Nzc1MTY0Mzc0MDE2MTM5NDQwNTM4NzMxODI0NTgzNjQyODg0MTQxMzA5MTQwNDgzNDU0ODMzNzcyMjYxNDQ2NTI2NTEiLCIxNDE5MTI2MDA3MTY5NTk4MDAxMTY3OTUwMTgwODQ1MzIyMjI2NzUyMDcyMTc2Nzc1Nzc1OTE1MDEwMTk3NDM4MjA1MzE2MTY3NDYxMSIsIjEiXSwicGlfYiI6W1siNzY3MDg0Nzg0NDAxNTExNjk1NzUyNjE4MzcyODE5Njk3Nzk1NzMxMjYyNzMwNzc5NzkxOTU1NDEzNDY4NDkwMTQwMTQzNjAyMTk3NyIsIjE0OTU3ODQ1NDcyNjMwMDE3MDk1ODIxODMzMjIyNTgwMTk0MDYxMjY2MTg2ODUxNjM0MDUzODk3NzY4NzM4MjUzNjYzMjUzNjUwODM1Il0sWyIxNzgzNTY0MjQ1ODQ4NDYyODYyNzU1NjMyOTg3NjkxOTA3NzMzMzkxMjAxMTIzNTMwODc1ODgzMjE3Mjg4MDAxMjgxMzM5NzAyMjEwNCIsIjE4MTAwODYxMTMwMTQ5Njc4MTUzMTMzMDI1MDMxNzA5ODk3MTIwMDk3MDk4NTkxMjk4ODE3MzY3NDkxOTIwNTUzMDM3MDExNjUwMjI4Il0sWyIxIiwiMCJdXSwicGlfYyI6WyI2MjE3ODY1OTQ5Mjk5OTkwNjQyODMyNTIzMjU2ODYzMDQ4OTMyMjEwNTQ2MDQ5MjAzMTg5MTEzMzYyODUxNDc2OTY2ODI0MTYyMTkxIiwiMTkwMTY5NDkyMjUyNzc3NTU2OTAwMTk2NDczODU4NTU5MzY5Njk5Mjg5OTQyMTA5MDU5OTI2MjgzMDE5Njc4ODM4MDM2NzA0MzY1MTAiLCIxIl0sInByb3RvY29sIjoiZ3JvdGgxNiIsImN1cnZlIjoiYm4xMjgifSwicHViX3NpZ25hbHMiOlsiMSIsIjI3MTUyNjc2OTg3MTI4NTQyMDY2ODA4NTkxOTk4NTczMDAwMzcwNDM2NDY0NzIyNTE5NTEzMzQ4ODkxMDQ5NjQ0ODEzNzE4MDE4IiwiMjMiLCIyNzc1Mjc2NjgyMzM3MTQ3MTQwODI0ODIyNTcwODY4MTMxMzc2NDg2NjIzMTY1NTE4NzM2NjA3MTg4MTA3MDkxODk4NDQ3MTA0MiIsIjIxNTQ1NzY4ODgzNTA5NjU3MzQwMjA5MTcxNTQ5NDQxMDA1NjAzMzA2MDEyNTEzOTMyMjIxMzcxNTk5NTAxNDk4NTM0ODA3NzE5Njg5IiwiMSIsIjIxNTQ1NzY4ODgzNTA5NjU3MzQwMjA5MTcxNTQ5NDQxMDA1NjAzMzA2MDEyNTEzOTMyMjIxMzcxNTk5NTAxNDk4NTM0ODA3NzE5Njg5IiwiMTY3OTMyMzAzOCIsIjMzNjYxNTQyMzkwMDkxOTQ2NDE5MzA3NTU5Mjg1MDQ4MzcwNDYwMCIsIjAiLCIxNzAwMjQzNzExOTQzNDYxODc4MzU0NTY5NDYzMzAzODUzNzM4MDcyNjMzOTk5NDI0NDY4NDM0ODkxMzg0NDkyMzQyMjQ3MDgwNjg0NCIsIjAiLCI1IiwiODQwIiwiMTIwIiwiMzQwIiwiNTA5IiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIl19XX19.eyJwcm9vZiI6eyJwaV9hIjpbIjcwMjI2MTEzODk5MzY1MDEzNDI2NTkwMjQ2Njk0NTczNTA3OTUwMTU5ODkzOTI1NzAzMDMwODQ4MzcyMTQ4MDc1MzYyNDg4NTE5MzYiLCIxMzg1OTcwODc3NTU0Mzk0Mjk3MTYxNTcxNTA1MTczNjM4MTc4NTEzODkzMjQ3ODc1Mzg3MjU5MTU0NDQxODk1ODkwOTU2MDQyOTU3NCIsIjEiXSwicGlfYiI6W1siMTE1MzQ5NjMxNDgwODQ0OTk0NDg5MDc3NzQxMTMxNjg1OTEyNDYyMjQ4OTg0MTU4ODAwMzY5NTA1MDYyMjU0ODkyMDA1NTc2NTA2NjUiLCIxNDA3MjA4Mjk1MTQ0Njc5NDk5MDk4NDcwNTE3ODA1OTY2NjI4NzM1NTEwNjc5MzUwMTg5MTE2ODgwNjE2NjUwMTUxMDkzMDY0MzQ0MSJdLFsiNDY3ODgyNDc3ODQ5ODA0NzE2OTEzNTk2NTg3MTYwNDgzNjkwMTQ1NjI5MDQ0NjQ0NjUzMzEyNzUwOTU4Mzg5MDU5MDkzNTY5ODQxNCIsIjEyODE5NzMwNTMyMDg0MTM4NDI0ODQ0MjExNDg4NjcxMTUyNDgwOTU1MzQ0MTA2NzU4NTE3NDEzODAxOTIzNTM3OTU3MzYzOTgwMjA0Il0sWyIxIiwiMCJdXSwicGlfYyI6WyIxNTUyMDYzNjk4OTY2MTg3NzExNDUwNjkwNDgxMDQxMzExNDI4NzQ5ODE1OTk2NDA5OTU2MTY5ODUyNjc4MzUwMDE1NjU1MjQzMDAwNCIsIjEyNjkyNzA3NDA3MTczMDg0OTM5NzQ1ODU5NzE0ODMxNDYyMDQ1ODg5NDA4NTk4NTI3MjU0ODA3NzkwNDk0NDY2Mjc5Njg3ODU5MjQ3IiwiMSJdLCJwcm90b2NvbCI6Imdyb3RoMTYiLCJjdXJ2ZSI6ImJuMTI4In0sInB1Yl9zaWduYWxzIjpbIjI3MTUyNjc2OTg3MTI4NTQyMDY2ODA4NTkxOTk4NTczMDAwMzcwNDM2NDY0NzIyNTE5NTEzMzQ4ODkxMDQ5NjQ0ODEzNzE4MDE4IiwiMTIxODQ5NzQwNzE0Mjc3NjgzNTIwMjcwMDM4NzgzMTkzMzgyNDkzODM4NDYxNjQ3MzAyMDQ1MDUzMjY5NTM1NTA2NDczOTExNzg4MDAiLCI4NzU2MDYwMjA1MDg2ODAzMzM1MjUyMzE5NzQ4NzQ4MzU0NzYxOTYxODE0MDEyNzI1NDk5ODczMzgyOTg4MDU2NDE4NjgwNjI4NjE5Il19`
	authInstance, err := NewVerifier(verificationKeyloader, stateResolvers)
	require.NoError(t, err)
	_, err = authInstance.FullVerify(context.Background(), token, request, pubsignals.WithAcceptedProofGenerationDelay(proofGenerationDelay))
	require.Error(t, err, errors.New("response type is not in accept profiles of the request"))
}

func TestVerifier_FullVerify_AcceptHeader(t *testing.T) {
	verifierID := "did:polygonid:polygon:mumbai:2qJ689kpoJxcSzB5sAFJtPsSBSrHF5dq722BHMqURL"
	callbackURL := "https://test.com/callback"
	reason := "age verification"
	acceptProfile := protocol.AcceptProfile{
		AcceptedVersion:     protocol.Iden3CommVersion1,
		Env:                 packers.MediaTypeZKPMessage,
		AcceptCircuits:      []circuits.CircuitID{circuits.AuthV2CircuitID},
		AcceptJwzAlgorithms: []protocol.JwzAlgorithms{protocol.JwzAlgorithmsGroth16},
	}

	accept, err := utils.BuildAcceptProfile([]protocol.AcceptProfile{acceptProfile})
	require.NoError(t, err)
	request := CreateAuthorizationRequestWithMessage(reason, "", verifierID, callbackURL, WithAccept(accept))
	request.ID = "28494007-9c49-4f1a-9694-7700c08865bf"
	request.ThreadID = "ee92ab12-2671-457e-aa5e-8158c205a985" // because it's used in the response
	token := `eyJhbGciOiJncm90aDE2IiwiY2lyY3VpdElkIjoiYXV0aFYyIiwiY3JpdCI6WyJjaXJjdWl0SWQiXSwidHlwIjoiYXBwbGljYXRpb24vaWRlbjMtemtwLWpzb24ifQ.eyJpZCI6IjljMGY5NjIzLWM1NmMtNDEwNC04ODk2LWVjMjgyYTNiMmExNyIsInR5cCI6ImFwcGxpY2F0aW9uL2lkZW4zY29tbS1wbGFpbi1qc29uIiwidHlwZSI6Imh0dHBzOi8vaWRlbjMtY29tbXVuaWNhdGlvbi5pby9hdXRob3JpemF0aW9uLzEuMC9yZXNwb25zZSIsInRoaWQiOiI3ZjM4YTE5My0wOTE4LTRhNDgtOWZhYy0zNmFkZmRiOGI1NDIiLCJmcm9tIjoiZGlkOnBvbHlnb25pZDpwb2x5Z29uOm11bWJhaToycVBETFhEYVUxeGExRVJUYjFYS0JmUENCM28yd0E0NnE0OW5laVhXd1kiLCJ0byI6ImRpZDpwb2x5Z29uaWQ6cG9seWdvbjptdW1iYWk6MnFKNjg5a3BvSnhjU3pCNXNBRkp0UHNTQlNySEY1ZHE3MjJCSE1xVVJMIiwiYm9keSI6eyJkaWRfZG9jIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy9ucy9kaWQvdjEiXSwiaWQiOiJkaWQ6cG9seWdvbmlkOnBvbHlnb246bXVtYmFpOjJxUERMWERhVTF4YTFFUlRiMVhLQmZQQ0IzbzJ3QTQ2cTQ5bmVpWFd3WSIsInNlcnZpY2UiOlt7ImlkIjoiZGlkOnBvbHlnb25pZDpwb2x5Z29uOm11bWJhaToycVBETFhEYVUxeGExRVJUYjFYS0JmUENCM28yd0E0NnE0OW5laVhXd1kjcHVzaCIsInR5cGUiOiJwdXNoLW5vdGlmaWNhdGlvbiIsInNlcnZpY2VFbmRwb2ludCI6Imh0dHBzOi8vcHVzaC1zdGFnaW5nLnBvbHlnb25pZC5jb20vYXBpL3YxIiwibWV0YWRhdGEiOnsiZGV2aWNlcyI6W3siY2lwaGVydGV4dCI6InhZK3RHWHUrOWlHMHZ6dFpMTTlKN25PcDNRbE1Uci85TmI3Qjl5Q0prbDlxcUpiZ1AvMExOL1VmTkxxQUk4RWZIcFhJVlVlTmVVUmNCNm82bWVMVlpJK2VvMlhvcDM2SE1iK2JyQnJTTjRqVHZWVkRDQXVXSkI2akV5Q3ZNRzlMaXp6blBsS3VQSE15dEdCVnZnV0laRFZBeVdZbTFyMk9PUzc4OU5DZm41MnNjV0VRVW5VRWdnTmpyWjlLdFpmb09RMlBDbUpqRXpDejg0ZUc3RGM2bEFvbi8ycTJJNVlLQk12RkhnT3c4N25wb0owczVrQ1RVVENjeVRlQmg2VXpLQk5aNElibndvR3ZYcG9FelBVZXZRdjRGbXVTaExYYVF3Vk9nalRBUXR0T2g2SjZhcmE4UHNndVFGQ3dNUTlxV2JjTjZYdXlScjk4TVlqbGxpL0VEN09TZzBsWVU5cUdLa1RaL2ZZN2VWZkYyeFFhOWZXK01WVzlxM2NJMjJzbkRwV28xY1ZYNWt1TWhpbmFsajZXV1Q0OTAvblNXak1rZ3JkL25CdXNiMHR4eG1jWDU3QUowcVlyMkNsK0pQb1FhcExiOEFTT3dGYU5kRDRZV3pKWXRXVmlDbktMZ3dQNDFHaGl5NVNWZE1vbU1sUy9kSGo2TVZPMjNyOVRiTDFrRy8rdkFIZWF0YkdvZ3p1OWd3SzlJckF3WS95THhMYVpQcHZzdlJLWjVBa2E1b1pkbmRNNkdLUkM0OVhoVXloQnNlY0N2Z1hNeGZGNVBnWGhROVFTb1drMzFXSWRiWG5vbmU2YmVNQkpLUVYzemg2MmpoZUFuV3czZW16dndKajRUUHU4WTJQZ2lDL3FaZXhlUVlKdFNkelJXZUFjK2N5a2ZwTXA0SmdrV2hBPSIsImFsZyI6IlJTQS1PQUVQLTUxMiJ9XX19XX0sIm1lc3NhZ2UiOm51bGwsInNjb3BlIjpbeyJpZCI6MjMsImNpcmN1aXRJZCI6ImNyZWRlbnRpYWxBdG9taWNRdWVyeU1UUFYyIiwicHJvb2YiOnsicGlfYSI6WyIyNjEwNjg1Nzc1MTY0Mzc0MDE2MTM5NDQwNTM4NzMxODI0NTgzNjQyODg0MTQxMzA5MTQwNDgzNDU0ODMzNzcyMjYxNDQ2NTI2NTEiLCIxNDE5MTI2MDA3MTY5NTk4MDAxMTY3OTUwMTgwODQ1MzIyMjI2NzUyMDcyMTc2Nzc1Nzc1OTE1MDEwMTk3NDM4MjA1MzE2MTY3NDYxMSIsIjEiXSwicGlfYiI6W1siNzY3MDg0Nzg0NDAxNTExNjk1NzUyNjE4MzcyODE5Njk3Nzk1NzMxMjYyNzMwNzc5NzkxOTU1NDEzNDY4NDkwMTQwMTQzNjAyMTk3NyIsIjE0OTU3ODQ1NDcyNjMwMDE3MDk1ODIxODMzMjIyNTgwMTk0MDYxMjY2MTg2ODUxNjM0MDUzODk3NzY4NzM4MjUzNjYzMjUzNjUwODM1Il0sWyIxNzgzNTY0MjQ1ODQ4NDYyODYyNzU1NjMyOTg3NjkxOTA3NzMzMzkxMjAxMTIzNTMwODc1ODgzMjE3Mjg4MDAxMjgxMzM5NzAyMjEwNCIsIjE4MTAwODYxMTMwMTQ5Njc4MTUzMTMzMDI1MDMxNzA5ODk3MTIwMDk3MDk4NTkxMjk4ODE3MzY3NDkxOTIwNTUzMDM3MDExNjUwMjI4Il0sWyIxIiwiMCJdXSwicGlfYyI6WyI2MjE3ODY1OTQ5Mjk5OTkwNjQyODMyNTIzMjU2ODYzMDQ4OTMyMjEwNTQ2MDQ5MjAzMTg5MTEzMzYyODUxNDc2OTY2ODI0MTYyMTkxIiwiMTkwMTY5NDkyMjUyNzc3NTU2OTAwMTk2NDczODU4NTU5MzY5Njk5Mjg5OTQyMTA5MDU5OTI2MjgzMDE5Njc4ODM4MDM2NzA0MzY1MTAiLCIxIl0sInByb3RvY29sIjoiZ3JvdGgxNiIsImN1cnZlIjoiYm4xMjgifSwicHViX3NpZ25hbHMiOlsiMSIsIjI3MTUyNjc2OTg3MTI4NTQyMDY2ODA4NTkxOTk4NTczMDAwMzcwNDM2NDY0NzIyNTE5NTEzMzQ4ODkxMDQ5NjQ0ODEzNzE4MDE4IiwiMjMiLCIyNzc1Mjc2NjgyMzM3MTQ3MTQwODI0ODIyNTcwODY4MTMxMzc2NDg2NjIzMTY1NTE4NzM2NjA3MTg4MTA3MDkxODk4NDQ3MTA0MiIsIjIxNTQ1NzY4ODgzNTA5NjU3MzQwMjA5MTcxNTQ5NDQxMDA1NjAzMzA2MDEyNTEzOTMyMjIxMzcxNTk5NTAxNDk4NTM0ODA3NzE5Njg5IiwiMSIsIjIxNTQ1NzY4ODgzNTA5NjU3MzQwMjA5MTcxNTQ5NDQxMDA1NjAzMzA2MDEyNTEzOTMyMjIxMzcxNTk5NTAxNDk4NTM0ODA3NzE5Njg5IiwiMTY3OTMyMzAzOCIsIjMzNjYxNTQyMzkwMDkxOTQ2NDE5MzA3NTU5Mjg1MDQ4MzcwNDYwMCIsIjAiLCIxNzAwMjQzNzExOTQzNDYxODc4MzU0NTY5NDYzMzAzODUzNzM4MDcyNjMzOTk5NDI0NDY4NDM0ODkxMzg0NDkyMzQyMjQ3MDgwNjg0NCIsIjAiLCI1IiwiODQwIiwiMTIwIiwiMzQwIiwiNTA5IiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIl19XX19.eyJwcm9vZiI6eyJwaV9hIjpbIjcwMjI2MTEzODk5MzY1MDEzNDI2NTkwMjQ2Njk0NTczNTA3OTUwMTU5ODkzOTI1NzAzMDMwODQ4MzcyMTQ4MDc1MzYyNDg4NTE5MzYiLCIxMzg1OTcwODc3NTU0Mzk0Mjk3MTYxNTcxNTA1MTczNjM4MTc4NTEzODkzMjQ3ODc1Mzg3MjU5MTU0NDQxODk1ODkwOTU2MDQyOTU3NCIsIjEiXSwicGlfYiI6W1siMTE1MzQ5NjMxNDgwODQ0OTk0NDg5MDc3NzQxMTMxNjg1OTEyNDYyMjQ4OTg0MTU4ODAwMzY5NTA1MDYyMjU0ODkyMDA1NTc2NTA2NjUiLCIxNDA3MjA4Mjk1MTQ0Njc5NDk5MDk4NDcwNTE3ODA1OTY2NjI4NzM1NTEwNjc5MzUwMTg5MTE2ODgwNjE2NjUwMTUxMDkzMDY0MzQ0MSJdLFsiNDY3ODgyNDc3ODQ5ODA0NzE2OTEzNTk2NTg3MTYwNDgzNjkwMTQ1NjI5MDQ0NjQ0NjUzMzEyNzUwOTU4Mzg5MDU5MDkzNTY5ODQxNCIsIjEyODE5NzMwNTMyMDg0MTM4NDI0ODQ0MjExNDg4NjcxMTUyNDgwOTU1MzQ0MTA2NzU4NTE3NDEzODAxOTIzNTM3OTU3MzYzOTgwMjA0Il0sWyIxIiwiMCJdXSwicGlfYyI6WyIxNTUyMDYzNjk4OTY2MTg3NzExNDUwNjkwNDgxMDQxMzExNDI4NzQ5ODE1OTk2NDA5OTU2MTY5ODUyNjc4MzUwMDE1NjU1MjQzMDAwNCIsIjEyNjkyNzA3NDA3MTczMDg0OTM5NzQ1ODU5NzE0ODMxNDYyMDQ1ODg5NDA4NTk4NTI3MjU0ODA3NzkwNDk0NDY2Mjc5Njg3ODU5MjQ3IiwiMSJdLCJwcm90b2NvbCI6Imdyb3RoMTYiLCJjdXJ2ZSI6ImJuMTI4In0sInB1Yl9zaWduYWxzIjpbIjI3MTUyNjc2OTg3MTI4NTQyMDY2ODA4NTkxOTk4NTczMDAwMzcwNDM2NDY0NzIyNTE5NTEzMzQ4ODkxMDQ5NjQ0ODEzNzE4MDE4IiwiMTIxODQ5NzQwNzE0Mjc3NjgzNTIwMjcwMDM4NzgzMTkzMzgyNDkzODM4NDYxNjQ3MzAyMDQ1MDUzMjY5NTM1NTA2NDczOTExNzg4MDAiLCI4NzU2MDYwMjA1MDg2ODAzMzM1MjUyMzE5NzQ4NzQ4MzU0NzYxOTYxODE0MDEyNzI1NDk5ODczMzgyOTg4MDU2NDE4NjgwNjI4NjE5Il19`
	authInstance, err := NewVerifier(verificationKeyloader, stateResolvers)
	require.NoError(t, err)
	_, err = authInstance.FullVerify(context.Background(), token, request, pubsignals.WithAcceptedProofGenerationDelay(proofGenerationDelay))
	require.NoError(t, err)
}

func TestVerifier_FullVerify_AcceptHeader_Auth_V3(t *testing.T) {
	verifierID := "did:iden3:polygon:amoy:x9X6FKAKt4gaPFHH72LCRMgsDH5JF65ndfFnQjBXz"
	callbackURL := "https://test.com/callback"
	reason := "age verification"
	request := CreateAuthorizationRequestWithMessage(reason, "", verifierID, callbackURL, WithAcceptedCircuits(circuits.AuthV3CircuitID))
	request.ID = "28494007-9c49-4f1a-9694-7700c08865bf"
	request.ThreadID = "ee92ab12-2671-457e-aa5e-8158c205a985"
	token := `eyJhbGciOiJncm90aDE2IiwiY2lyY3VpdElkIjoiYXV0aFYzIiwiY3JpdCI6WyJjaXJjdWl0SWQiXSwidHlwIjoiYXBwbGljYXRpb24vaWRlbjMtemtwLWpzb24ifQ.eyJpZCI6ImEyNTBjNmRjLWY3YzktNDU5YS1hYTBkLTU1NGM5NjRmMmVhMyIsInR5cCI6ImFwcGxpY2F0aW9uL2lkZW4zLXprcC1qc29uIiwidHlwZSI6Imh0dHBzOi8vaWRlbjMtY29tbXVuaWNhdGlvbi5pby9hdXRob3JpemF0aW9uLzEuMC9yZXNwb25zZSIsInRoaWQiOiI4OTc4ODVlYS02NTE4LTRiZDItODg2Yi0yM2QzOGRlMTJmNTkiLCJib2R5Ijp7InNjb3BlIjpbeyJpZCI6MSwiY2lyY3VpdElkIjoiY3JlZGVudGlhbEF0b21pY1F1ZXJ5VjMtYmV0YS4xIiwicHJvb2YiOnsicGlfYSI6WyIyMTM1ODA1ODk2OTM1NTkwMTU1NDkxNzkwNzQ0MDc1NzM5ODUyMTY1NzY4ODE4ODU2MTQyNDkwODA5NTE5MzgzNjI0MzI2NjgxMjg4NyIsIjIwMzE1NTA0MDAwODE0NjEwNTI3NDc5ODg0MzE5OTM1MDIyNDg0NzA2Mzc2MTcwNDMwMjA3NTUzOTE5MDYzMDY2Mzk2MTA0NTUwNTQ4IiwiMSJdLCJwaV9iIjpbWyIxMDk2MzcxOTI5OTg1Mzk5NDQ2ODYwNDA1NTkzMjgxNDY1OTgwOTkxNDk4ODM5MDQwMzM5NTUwMTMyNDMxNTgzNjk3NzgwMTUxMTY0IiwiNzk1NDExODc2NTIxNzE5NDYzOTEyMDAwMjQzNjUzNDcyMzcyNDY5OTUzMTAwMTA1MzIxNDAwOTc3ODEwNzgxOTQ1MTIyMjUyNTAzMiJdLFsiNjYyNzIxMjQ3ODUzMDM5MzE0NTQ3NjYwMzY5MjMwMjc1OTAxNjU1MTc3MTYyNjY4MTk5NDc5MDI0OTYwMjY0OTU1MjkxNDcyMTU2NSIsIjk5MDcyMTE2Njc4MDY1NTg3NTAwMDUwMDI5MDI0NTM1MzYxODkwMzc1NDkzMDIxODI0NjA2NDkyODQ1NzkyNDQwNjM5NjkyNzIiXSxbIjEiLCIwIl1dLCJwaV9jIjpbIjE0MDYzNTAwMTM1Njg5NDE1NTExMDk2ODczNzU0OTI4NjExNzYzMzE0MzE4ODYwNjQ5ODQzNTk0NTA4NjEzMjYyOTY1NDk1MzU0ODgxIiwiMTU0NjMwOTYzNDUxOTEwOTI0NDk2ODk2NTQzOTY1MDQwNDA4MzIwMDgyMDEyMjYwMzU3NTQ3OTY0ODU1OTIwNzQzMTg5NjY2MDYyMzQiLCIxIl0sInByb3RvY29sIjoiZ3JvdGgxNiIsImN1cnZlIjoiYm4xMjgifSwicHViX3NpZ25hbHMiOlsiMSIsIjIzNTA4NDgxMTczNTUxNDczNTg1MjI0NTU4Njg3MDcyODI4NDAwOTEzMTA0MTYzMDQ5NjM4NTM5MDE0OTI5MDIzMTU2MDMyMjU3IiwiMTU1MjI0MDA5Mzk5MDcyOTQ1MDUwNzM5ODYzOTk0NzIxODg4NDA1ODM2MjQ3NDY0MzkzMjgwOTIzNTQ5NDUxNzc2Njc4Mjc2Mzc0MDAiLCI0MTAxNTc2Mjc2NTU0MDAxMzM2MzE1ODYyMjI1Mjk5NTQ0MDAxNzcwMzMxNzMwNjk2MzkyMzQ4MzM5MzI3NDgxMTE3MzU3NjQ4OTY2IiwiMCIsIjAiLCIxIiwiMSIsIjI0NTM2NjMzNDcwMDM0NTM4NjI4MTc4ODMwNDg2MDc2MTc1MjQ5MDUyOTY0Mzk1OTQ2MTgzNDcyMTc4MjI0Njg4MzY5NTA1MDI1IiwiMSIsIjE1NTIyNDAwOTM5OTA3Mjk0NTA1MDczOTg2Mzk5NDcyMTg4ODQwNTgzNjI0NzQ2NDM5MzI4MDkyMzU0OTQ1MTc3NjY3ODI3NjM3NDAwIiwiMTc1NjcyNjExOSIsIjI2NzgzMTUyMTkyMjU1ODAyNzIwNjA4MjM5MDA0MzMyMTc5Njk0NCIsIjE3MDQwNjY3NDA3MTk0NDcxNzM4OTU4MzQwMTQ2NDk4OTU0NDU3MTg3ODM5Nzc4NDAyNTkxMDM2NTM4NzgxMzY0MjY2ODQxOTY2IiwiMCIsIjExIiwiMSIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjEiLCIyNDUzNjYzMzQ3MDAzNDUzODYyODE3ODgzMDQ4NjA3NjE3NTI0OTA1Mjk2NDM5NTk0NjE4MzQ3MjE3ODIyNDY4ODM2OTUwNTAyNSIsIjAiXX1dfSwiZnJvbSI6ImRpZDppZGVuMzpwb2x5Z29uOmFtb3k6eEI3eTJzbTYyeld2RW12aFYzUWNmRGpqMk5qZVB5OVNRTGkzTU02Y0MiLCJ0byI6ImRpZDppZGVuMzpwb2x5Z29uOmFtb3k6eDlYNkZLQUt0NGdhUEZISDcyTENSTWdzREg1SkY2NW5kZkZuUWpCWHoifQ.eyJwcm9vZiI6eyJwaV9hIjpbIjk2MTE1NjczMDk1ODU5NzYwNjUyOTIzOTc4NzQ0MjkxOTQ0NTk4NTgwMjQ2MjI4MjIyNDE2OTQ1NTAyMjQwNDcxNzQ3NDAzMjA5MDAiLCIxNDk5NDc4NzQ3MTc1ODE0NzI5NjI0ODExODU0OTY5ODY4NzcwMzE2NzkxOTQzMjM2MTI0MTcyODUyMjk4NTU1MTIxNzg5MTExMjYxMCIsIjEiXSwicGlfYiI6W1siMTM4OTE5NjQ3MDcxNzg2OTY1NzI0MzI5ODE2MTA3NTQ4Mzc2MDgxOTczNzU0MDE2MzUyODYyOTM0NDE4NzI1MDY1MTU1MDQ1MTg2MjgiLCI5MDIzOTA3OTgwMTU2MDc3Njg0NDQ5MTU0OTI4NTExMTI1OTk2Njg1MTI5NjY5ODA1NTY4NTEyMTA0OTU4MDU3MDM1MTM1NDUzODc1Il0sWyIxMTAyMDA0NDIyMDIxMjgzNDAxMDM0NzIyNTM3MzUxMDQ5NjU0NTYwMTcwNjM3MzcwNTg3NTQ5MjY5MTc1ODI5MjQ4MDMyNDMzMzM2OCIsIjEyNzE0NzQxMjc1OTA5OTQ2NTIxNzQxNjg1MTc0NDgyODcxNzE4OTkxMTI5MjAyMjU5NzA3MTc2Nzg3OTM5NTY1OTIzMTg3MjQ2MzQ0Il0sWyIxIiwiMCJdXSwicGlfYyI6WyIxMzcyNjYwNzYwNTIxMTUyNDgyODMwMDU4MDkxNDA3MTc0NTMwMjA0NzE0MDYzNzkzMzYxNDU0NjY2MDUwNjkzMjc0MDIyNDU3MDE4NCIsIjQ1NzU5NjUzNzQ5MTk0ODc1MjYzOTU1NzcyODc5MTE5NzAyNTY1OTA1NTgyMTM2MzU3NTgyMzc4MDk5MzI0MzkwNjkxOTkwNzIyOTAiLCIxIl0sInByb3RvY29sIjoiZ3JvdGgxNiIsImN1cnZlIjoiYm4xMjgifSwicHViX3NpZ25hbHMiOlsiMjM1MDg0ODExNzM1NTE0NzM1ODUyMjQ1NTg2ODcwNzI4Mjg0MDA5MTMxMDQxNjMwNDk2Mzg1MzkwMTQ5MjkwMjMxNTYwMzIyNTciLCI5OTEwODQ1NTczMTk1NDk5NDk3MTk0Njk5MDMwNjA3MTE2MzE0NjA2ODA0NDQyMDM3MzI5NzQ3Mjg1ODg0NTY3NTEzMzk3MDY1NzgiLCIyMzkxNTgxMzQyMzc3MDEyNDM5OTg5Nzk2NzE1NDk5NTkzNjY3MjkwMjk5NzkwNDIxNDAxNzY1NjA3ODYzOTYyMTY0OTUwODAyODczIl19`
	authInstance, err := NewVerifier(verificationKeyloader, stateResolvers)
	require.NoError(t, err)
	_, err = authInstance.FullVerify(context.Background(), token, request, pubsignals.WithAcceptedProofGenerationDelay(proofGenerationDelay))
	require.NoError(t, err)
}

func TestVerifier_FullVerify_AcceptHeader_Auth_V3_8_32(t *testing.T) {
	verifierID := "did:iden3:polygon:amoy:x8ydGtvvbrQHseWAegbQ13G4VP5HVqmuvCtPQNkwD"
	callbackURL := "https://test.com/callback"
	reason := "age verification"
	request := CreateAuthorizationRequestWithMessage(reason, "", verifierID, callbackURL, WithAcceptedCircuits(circuits.AuthV3_8_32CircuitID))
	request.ID = "28494007-9c49-4f1a-9694-7700c08865bf"
	request.ThreadID = "ee92ab12-2671-457e-aa5e-8158c205a985"
	token := `eyJhbGciOiJncm90aDE2IiwiY2lyY3VpdElkIjoiYXV0aFYzLTgtMzIiLCJjcml0IjpbImNpcmN1aXRJZCJdLCJ0eXAiOiJhcHBsaWNhdGlvbi9pZGVuMy16a3AtanNvbiJ9.eyJpZCI6IjE2MDZkOTQ4LWE4NTQtNDZlMy04YTJiLTg4ZmNjNjJjOGNiNSIsInR5cCI6ImFwcGxpY2F0aW9uL2lkZW4zLXprcC1qc29uIiwidHlwZSI6Imh0dHBzOi8vaWRlbjMtY29tbXVuaWNhdGlvbi5pby9hdXRob3JpemF0aW9uLzEuMC9yZXNwb25zZSIsInRoaWQiOiIzMjAxM2I2Ni1mY2M5LTQ3MjktODhkMC1jNjRlNmQwZDc5YjkiLCJib2R5Ijp7InNjb3BlIjpbeyJpZCI6MSwiY2lyY3VpdElkIjoiY3JlZGVudGlhbEF0b21pY1F1ZXJ5VjMtYmV0YS4xIiwicHJvb2YiOnsicGlfYSI6WyI5MzA3MzA5NTA1NTEzNDIxNjA5NjAwOTE5Njk4NTk3NzUyNTQwNzY4MjQxMTU2MzI3MDE0MjQyMDcyODg1MDAxODk1NzExOTQ2NzE4IiwiNTYxNjAwNjQ4OTY4MjIxMDEzMjQyODg2MTExODg1NDQ3Nzk4MDgwMDc2NTk4ODEyOTA0MjU5MzE3ODA2Nzk2MzY2MjQzMTk4OTgwOCIsIjEiXSwicGlfYiI6W1siODY4MjEwNTA3NjQwODY5NDk1NTc2MDkxNDAzMjkxODEzMjc5Mjk2NDMzMjg1MzM5ODU1MTQxMzY3NTg4NDg1OTQ1MzU2MzM1ODU3OCIsIjkxODkyMTQzODY0OTg5OTE4MTcwNTEwMzYzMzc5NTQ1OTg1NTU3ODYxNzA4ODQ5MTI0MTk0MDM1Njg4NzQ0MTc4OTU4OTIxNDAwMjMiXSxbIjExMTc1OTA4ODM3MzQxNzI4MDU4MDY2MjkxMzgzNzI2MjczMzIwMjQyMzUwODgzMjM4MTY3NzE0NjA2MzUyMjY1NTk4MDA0MzkwMjMiLCIxMzcwNzgwMjg3MTk3ODU3ODgyMTQ1MjU0ODkwNjA4NDI3NDIxMzgxMDQ1MjY4MDQzNDUxOTg4ODE4NjkwODg3NjIzODQ4ODE5ODYyMCJdLFsiMSIsIjAiXV0sInBpX2MiOlsiMTI2NDk0OTgwNTM5NjEyMDY1MzY5NjQzNjc5MTI4Mjc2ODUzNDkyMjcwOTU2NDAzNTg5Mzk0NDUxMzM1ODM5MDE4MzI4MTg3NjI0NjIiLCIyODQxMjAxOTU5MTIyMzkyOTEzMzYyNTQxNDA0NTA4MDkzNDg2OTc5MzU2Mjk0MDI1NjY3MDk0MDkwNDA1Mzg3MDMxNDU3MTQ4NzU2IiwiMSJdLCJwcm90b2NvbCI6Imdyb3RoMTYiLCJjdXJ2ZSI6ImJuMTI4In0sInB1Yl9zaWduYWxzIjpbIjEiLCIyMDIyOTA1MDAyMTA1NjcxMzQ1ODYzMzI2NDIwODA1ODE2ODIyNTUwNjE1MjUyNTU3Mzg2NzI0NjgxMTkwNjc0NTkwNTc3OTQ1NyIsIjE4ODc5MTMwMzUxOTE4MTc5OTE3MTQ5MTkxNjU4OTI4NTE0NzM3ODIwNDkxNzUyMjEwMTMwMzIwMTYxNjgxNDUyMjA3Mzg1NTQ5MDc1IiwiMTEwMjAyMDkxNTU2ODAxOTUxNTYzNTM0MjUwOTY0NTkzNDc2ODY0Nzc1NDM3MjkyODY4OTM3MTAzOTAxNTgyNDQzNDA5MzUyNzcxOTMiLCIwIiwiMCIsIjEiLCIxIiwiMjE5NjI0ODIxNTkzNDU4NjgzNTAxMzE1MTMwODgzMDQwMzM5NTMxODA0ODY2NjEwNjU4NDU3ODE3OTU2MzI0ODEyNTUwMzU2NDkiLCIxIiwiMTg4NzkxMzAzNTE5MTgxNzk5MTcxNDkxOTE2NTg5Mjg1MTQ3Mzc4MjA0OTE3NTIyMTAxMzAzMjAxNjE2ODE0NTIyMDczODU1NDkwNzUiLCIxNzU2NzI2MDIwIiwiMjY3ODMxNTIxOTIyNTU4MDI3MjA2MDgyMzkwMDQzMzIxNzk2OTQ0IiwiMTcwNDA2Njc0MDcxOTQ0NzE3Mzg5NTgzNDAxNDY0OTg5NTQ0NTcxODc4Mzk3Nzg0MDI1OTEwMzY1Mzg3ODEzNjQyNjY4NDE5NjYiLCIwIiwiMTEiLCIxIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMSIsIjIxOTYyNDgyMTU5MzQ1ODY4MzUwMTMxNTEzMDg4MzA0MDMzOTUzMTgwNDg2NjYxMDY1ODQ1NzgxNzk1NjMyNDgxMjU1MDM1NjQ5IiwiMCJdfSx7ImlkIjoyLCJjaXJjdWl0SWQiOiJsaW5rZWRNdWx0aVF1ZXJ5MTAtYmV0YS4xIiwidnAiOnsiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiXSwidHlwZSI6IlZlcmlmaWFibGVQcmVzZW50YXRpb24iLCJ2ZXJpZmlhYmxlQ3JlZGVudGlhbCI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsImh0dHBzOi8vcmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbS9pZGVuMy9jbGFpbS1zY2hlbWEtdm9jYWIvbWFpbi9zY2hlbWFzL2pzb24tbGQva3ljLXY0Lmpzb25sZCJdLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiS1lDQWdlQ3JlZGVudGlhbCJdLCJjcmVkZW50aWFsU3ViamVjdCI6eyJ0eXBlIjoiS1lDQWdlQ3JlZGVudGlhbCIsImJpcnRoZGF5IjoxOTk2MDQyNCwiZG9jdW1lbnRUeXBlIjo5OX19fSwicHJvb2YiOnsicGlfYSI6WyIxOTA5MDQ4MTUxODA4OTI1MDUxNzI1MzM2MTQ4Njg4OTE1MjA2Mjk3MDI4NTg1NDQzNDU3MTc1NzE1Nzg4MzMwMTY2MzE2Mzk2NTgwMCIsIjEwNjQxOTMwNzMzNzA3MzkxNzMxNzIwNDIxMzgzNDMzNTg5NDI0ODk1MDIwNTg0NDQ1OTk5ODEzMzc3MTA0MDY1Nzg2Njk0NjQ5MTQiLCIxIl0sInBpX2IiOltbIjc3OTg2MTA3Mzc2OTIxNzI5NDU3ODEwMjcyNTg2NTU4OTUxMzA2NDA1MTg1MjcxMDM4NDAzNDcyODMyNjQ3NDc2NzA5NjE3ODI5OTIiLCIxMDkyNjk0MDAzMDI1MTE3NTc0MzkwNjAzMTk3MTk2NzI2OTM0MTA2NDkwNjY0MzY3NjgxODA3MDE3MTI3NDU5MTU5NTMzMDgxMzE2OCJdLFsiMjA3Njk1Nzk0Nzg2NTY5NTkzNDgwNTE1NDE3NjI3MDE1MDU3NDQ1NjE4OTI4OTQwNDMxMTEwOTgzMzAxODEzNjU2NDA0NjMyNDIyNTAiLCI0MTcyNzcxNzQ0Mzg0MDY1MzgxMTY3NTgzNjAwMzM5NDAzMjMxODUxMzUyNDQyNDg4MDI2NDMxMzMyNTI2NzA0MTkxOTAxNTM2ODg5Il0sWyIxIiwiMCJdXSwicGlfYyI6WyI2NzEzMDcwNjQ5MTcxMzA0ODMxNjgzNDEwOTgxODk0MzE5MjkzMDgwOTg3NzAzMDU5NTE4ODY5Mzg0MDkxNjAwMzU1MDQzODk2NjA2IiwiMTI1OTExNzA3OTc4MzU2ODM4NjY0MjQ4MDI4NjgwMTQyNzUxNjkzODk0NzQ0NTA1NDIwMTQ1NTEzMTkxNDE1MDg3MjI0ODI5MTgxNiIsIjEiXSwicHJvdG9jb2wiOiJncm90aDE2IiwiY3VydmUiOiJibjEyOCJ9LCJwdWJfc2lnbmFscyI6WyIxMTAyMDIwOTE1NTY4MDE5NTE1NjM1MzQyNTA5NjQ1OTM0NzY4NjQ3NzU0MzcyOTI4Njg5MzcxMDM5MDE1ODI0NDM0MDkzNTI3NzE5MyIsIjEiLCIxOTk2MDQyNCIsIjk5IiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCI0NTg0NDQ3MTQ3MDYxMjcyNjQ2NDA1NzQ5ODc3MDQ4OTk5MTU5MjA1ODc1ODAwNjU2NjgzMjE5OTgyNDM0MzYwNDkzNjgzNjYyMzY5IiwiMTAwNzA0NTgxNzI3Njg2ODk2MTU3NDMyMjgwMDIyMTUwMTUzMTUwMTcwNDU3MzQyODI2OTI4ODY3NDAzNDI4OTUwNzc1MjcwNTE3NzUiLCIxMzM2MjA0Mjk3Nzk2NTg4NTkwMzgyMDU1NzUxMzUzNDA2NTgwMjg5NjI4ODMwMDAxNzE5OTcwMDY3NzYzMzcyMTQwNTgwNTY3NzQ0MiIsIjEzMzYyMDQyOTc3OTY1ODg1OTAzODIwNTU3NTEzNTM0MDY1ODAyODk2Mjg4MzAwMDE3MTk5NzAwNjc3NjMzNzIxNDA1ODA1Njc3NDQyIiwiMTMzNjIwNDI5Nzc5NjU4ODU5MDM4MjA1NTc1MTM1MzQwNjU4MDI4OTYyODgzMDAwMTcxOTk3MDA2Nzc2MzM3MjE0MDU4MDU2Nzc0NDIiLCIxMzM2MjA0Mjk3Nzk2NTg4NTkwMzgyMDU1NzUxMzUzNDA2NTgwMjg5NjI4ODMwMDAxNzE5OTcwMDY3NzYzMzcyMTQwNTgwNTY3NzQ0MiIsIjEzMzYyMDQyOTc3OTY1ODg1OTAzODIwNTU3NTEzNTM0MDY1ODAyODk2Mjg4MzAwMDE3MTk5NzAwNjc3NjMzNzIxNDA1ODA1Njc3NDQyIiwiMTMzNjIwNDI5Nzc5NjU4ODU5MDM4MjA1NTc1MTM1MzQwNjU4MDI4OTYyODgzMDAwMTcxOTk3MDA2Nzc2MzM3MjE0MDU4MDU2Nzc0NDIiLCIxMzM2MjA0Mjk3Nzk2NTg4NTkwMzgyMDU1NzUxMzUzNDA2NTgwMjg5NjI4ODMwMDAxNzE5OTcwMDY3NzYzMzcyMTQwNTgwNTY3NzQ0MiIsIjEzMzYyMDQyOTc3OTY1ODg1OTAzODIwNTU3NTEzNTM0MDY1ODAyODk2Mjg4MzAwMDE3MTk5NzAwNjc3NjMzNzIxNDA1ODA1Njc3NDQyIl19LHsiaWQiOjMsImNpcmN1aXRJZCI6ImxpbmtlZE11bHRpUXVlcnkxMC1iZXRhLjEiLCJwcm9vZiI6eyJwaV9hIjpbIjk1NTkwMDc5MzM3MjMzNDM1NTY5ODI5NjE1NDgzNDI2NDgyNTY1NzMxMzQ2MDkyNDY0Njg0NTQ1ODMwMDExMTY2MjQ1NTQxNDM0NjMiLCIxNjcwNDUzMTQ4MDAzNzY3Njg4NDU2MTE2OTE3NzMwODY2MjU5MDgwNjY2MjQzMjM1NDAxMTMwNTgxOTY3NDE0NzkzNTI5NDU5MDg4NCIsIjEiXSwicGlfYiI6W1siMTQyODI0NzAyNjM0NjIyODI2MzI4MjI2NjIwMTUwODk1Mzg3NzEwNTkyNDY1NDQyNDI4NzkyMjkwOTI0NTIwNjc5MjgyMDgzNjAwNTAiLCIxODE0ODQzMjg0MzI2NTM3Mzc2OTU1NTczMTA0MTA2MTQ0MDA2NTc4NDQ5MTQ1MTQ3NzU2Mzc0NjI0MjU2MDU3MDkxMDgyMTYzNTUwMSJdLFsiMTgxNTY0OTY2Njc2MzgyOTkyNDc4MDI2NTI0OTU0NjQ3NDMwMjY5NTk3OTc2NDM4MzA0NzI3ODgyOTg1MTA5MzE5NjQ5MTk0MDkxMTgiLCIxNDgwNTE1NTI1NjIyNTQyMjEwNjExODgzODY1MTU2NzkyNDY2MTI4ODE1NTA5MTc5MTEzNDA4ODQyNTEyMDUwNzY5Mzc3MDc1MTYxNCJdLFsiMSIsIjAiXV0sInBpX2MiOlsiOTA3MTY1NTAxNDIzNTQ2NzEyMzIxMjMwNDU3MjcxOTA2MzcyMzIzMTY5NjU4Nzg0NzcxMTAzNDU0MjI4NzUyMzExMzk1MjU0ODU1OSIsIjE5ODQ0NDYzMDQzMjEyMTcyNzIyNjQ5Njc5NzQ5MzYyMDAwNTkxNTUyNDU4ODgzOTkyNDQwMDE1NDQ2NjE1ODc0Nzg0ODgxMDkyMDExIiwiMSJdLCJwcm90b2NvbCI6Imdyb3RoMTYiLCJjdXJ2ZSI6ImJuMTI4In0sInB1Yl9zaWduYWxzIjpbIjExMDIwMjA5MTU1NjgwMTk1MTU2MzUzNDI1MDk2NDU5MzQ3Njg2NDc3NTQzNzI5Mjg2ODkzNzEwMzkwMTU4MjQ0MzQwOTM1Mjc3MTkzIiwiMSIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCI2NTkwMTc5NTk3NDM3NDcyNjUxOTU2NjA1NzY1ODUyMzg3MTQ4NTA0NzQyNTUwNzE1OTY0MTEwMjQ2NjIxMjYzMTc4NzQ4NTE2Njg0IiwiMTMzNjIwNDI5Nzc5NjU4ODU5MDM4MjA1NTc1MTM1MzQwNjU4MDI4OTYyODgzMDAwMTcxOTk3MDA2Nzc2MzM3MjE0MDU4MDU2Nzc0NDIiLCIxMzM2MjA0Mjk3Nzk2NTg4NTkwMzgyMDU1NzUxMzUzNDA2NTgwMjg5NjI4ODMwMDAxNzE5OTcwMDY3NzYzMzcyMTQwNTgwNTY3NzQ0MiIsIjEzMzYyMDQyOTc3OTY1ODg1OTAzODIwNTU3NTEzNTM0MDY1ODAyODk2Mjg4MzAwMDE3MTk5NzAwNjc3NjMzNzIxNDA1ODA1Njc3NDQyIiwiMTMzNjIwNDI5Nzc5NjU4ODU5MDM4MjA1NTc1MTM1MzQwNjU4MDI4OTYyODgzMDAwMTcxOTk3MDA2Nzc2MzM3MjE0MDU4MDU2Nzc0NDIiLCIxMzM2MjA0Mjk3Nzk2NTg4NTkwMzgyMDU1NzUxMzUzNDA2NTgwMjg5NjI4ODMwMDAxNzE5OTcwMDY3NzYzMzcyMTQwNTgwNTY3NzQ0MiIsIjEzMzYyMDQyOTc3OTY1ODg1OTAzODIwNTU3NTEzNTM0MDY1ODAyODk2Mjg4MzAwMDE3MTk5NzAwNjc3NjMzNzIxNDA1ODA1Njc3NDQyIiwiMTMzNjIwNDI5Nzc5NjU4ODU5MDM4MjA1NTc1MTM1MzQwNjU4MDI4OTYyODgzMDAwMTcxOTk3MDA2Nzc2MzM3MjE0MDU4MDU2Nzc0NDIiLCIxMzM2MjA0Mjk3Nzk2NTg4NTkwMzgyMDU1NzUxMzUzNDA2NTgwMjg5NjI4ODMwMDAxNzE5OTcwMDY3NzYzMzcyMTQwNTgwNTY3NzQ0MiIsIjEzMzYyMDQyOTc3OTY1ODg1OTAzODIwNTU3NTEzNTM0MDY1ODAyODk2Mjg4MzAwMDE3MTk5NzAwNjc3NjMzNzIxNDA1ODA1Njc3NDQyIl19XX0sImZyb20iOiJkaWQ6aWRlbjM6cG9seWdvbjphbW95OnhCdWNXRURLNnRIQjJrTlpMWUpmMTVVMldnN0VaMUVGTDVGRkpORThBIiwidG8iOiJkaWQ6aWRlbjM6cG9seWdvbjphbW95Ong4eWRHdHZ2YnJRSHNlV0FlZ2JRMTNHNFZQNUhWcW11dkN0UFFOa3dEIn0.eyJwcm9vZiI6eyJwaV9hIjpbIjk5MzY1MjIyMTE2ODY0ODE1MTUxMDE1NzgwMzMxMTI1ODkxMDI3MTQwMzkxNjE2MjU5NTA1MTI0MjY1NDYwNjc1NzgzMjU1MjU0OTgiLCIxNDY2NjMxMjY3ODkwMzU1MzE5NTMxOTQwMTAwMDc3OTA4MzcxNzc2MjUzNzA1MTYwMjA5NzI3MDUzMjY4OTEyNjQ3NDM5MjA5MDIzNyIsIjEiXSwicGlfYiI6W1siMTAwMjgxMzM5NjI2MTE2MTQ1MDAwNTU5NzM5MzE4NTc3MTgwOTc1NDMwNzgyMDAyNDcyMzQxNDgwODU1MDkzOTA4NTQ2OTY1NDA3NTIiLCIxNTQ3NTQzNDY3MzE0NTcxMzM4OTk3OTg5ODY2ODU1Njg2NjcwMDAyMjc5MDQzNDAzNTI3ODg5MDM2NDIyNjUzMTk1OTQ4ODExNzY0NCJdLFsiMTk0MDY5MjA3MTI5ODQyNTcwNzQ3NzIxOTUwMjg2NjM1MTYzNDU0MTYwMzIyNjYyODEzNzY0MjA2OTM4MDc1ODE4MDA4NTk3Mzk2NTciLCI2Njc3OTk3MTA0MTc4OTcwNjE5MzIzMzI4MzcwMTc0NjQ3MzY0MDg1NDYxOTQ4Nzk4Mzc4NDk5Mzc2ODEwMDg0NDYwNzQ2Mjk3ODEwIl0sWyIxIiwiMCJdXSwicGlfYyI6WyIxOTY1OTY5NzQ1ODAyODU1NTA0NjYzOTM0MDE3NTMyNjE5MDE5MzU5NzAyNDk0NzI0MzI2NDAxMzQwMjcxMTYzMTg4MjQ2MjY2MzY5NyIsIjIwNDExNjkxNjQ0NTkyNjU5NTgyMDIyOTczNzY1NDk1Mjc0MzE2ODk5ODMyNTM4NDQ1MzEzOTE2NTU4MDg2OTE4OTkwMDU0MjE4OTciLCIxIl0sInByb3RvY29sIjoiZ3JvdGgxNiIsImN1cnZlIjoiYm4xMjgifSwicHViX3NpZ25hbHMiOlsiMjAyMjkwNTAwMjEwNTY3MTM0NTg2MzMyNjQyMDgwNTgxNjgyMjU1MDYxNTI1MjU1NzM4NjcyNDY4MTE5MDY3NDU5MDU3Nzk0NTciLCIxMTA4ODY3MTA0OTEzNzk5MDE0NDUxMTc4ODExMTUzMzY1MTIxNzIxOTA4MzQxNjIyMzg3OTE5MDQyNDk5MjYwMTExNTk2MTc0OTc2MiIsIjIzOTE1ODEzNDIzNzcwMTI0Mzk5ODk3OTY3MTU0OTk1OTM2NjcyOTAyOTk3OTA0MjE0MDE3NjU2MDc4NjM5NjIxNjQ5NTA4MDI4NzMiXX0`
	authInstance, err := NewVerifier(verificationKeyloader, stateResolvers)
	require.NoError(t, err)
	_, err = authInstance.FullVerify(context.Background(), token, request, pubsignals.WithAcceptedProofGenerationDelay(proofGenerationDelay))
	require.NoError(t, err)
}

func TestVerifier_FullVerify_AcceptHeader_NotSupported(t *testing.T) {
	verifierID := "did:polygonid:polygon:mumbai:2qJ689kpoJxcSzB5sAFJtPsSBSrHF5dq722BHMqURL"
	callbackURL := "https://test.com/callback"
	reason := "age verification"
	acceptProfile := protocol.AcceptProfile{
		AcceptedVersion:     protocol.Iden3CommVersion1,
		Env:                 packers.MediaTypeZKPMessage,
		AcceptCircuits:      []circuits.CircuitID{circuits.AuthCircuitID},
		AcceptJwzAlgorithms: []protocol.JwzAlgorithms{protocol.JwzAlgorithmsGroth16},
	}

	accept, err := utils.BuildAcceptProfile([]protocol.AcceptProfile{acceptProfile})
	require.NoError(t, err)
	request := CreateAuthorizationRequestWithMessage(reason, "", verifierID, callbackURL, WithAccept(accept))
	request.ID = "28494007-9c49-4f1a-9694-7700c08865bf"
	request.ThreadID = "ee92ab12-2671-457e-aa5e-8158c205a985" // because it's used in the response
	token := `eyJhbGciOiJncm90aDE2IiwiY2lyY3VpdElkIjoiYXV0aFYyIiwiY3JpdCI6WyJjaXJjdWl0SWQiXSwidHlwIjoiYXBwbGljYXRpb24vaWRlbjMtemtwLWpzb24ifQ.eyJpZCI6IjljMGY5NjIzLWM1NmMtNDEwNC04ODk2LWVjMjgyYTNiMmExNyIsInR5cCI6ImFwcGxpY2F0aW9uL2lkZW4zY29tbS1wbGFpbi1qc29uIiwidHlwZSI6Imh0dHBzOi8vaWRlbjMtY29tbXVuaWNhdGlvbi5pby9hdXRob3JpemF0aW9uLzEuMC9yZXNwb25zZSIsInRoaWQiOiI3ZjM4YTE5My0wOTE4LTRhNDgtOWZhYy0zNmFkZmRiOGI1NDIiLCJmcm9tIjoiZGlkOnBvbHlnb25pZDpwb2x5Z29uOm11bWJhaToycVBETFhEYVUxeGExRVJUYjFYS0JmUENCM28yd0E0NnE0OW5laVhXd1kiLCJ0byI6ImRpZDpwb2x5Z29uaWQ6cG9seWdvbjptdW1iYWk6MnFKNjg5a3BvSnhjU3pCNXNBRkp0UHNTQlNySEY1ZHE3MjJCSE1xVVJMIiwiYm9keSI6eyJkaWRfZG9jIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy9ucy9kaWQvdjEiXSwiaWQiOiJkaWQ6cG9seWdvbmlkOnBvbHlnb246bXVtYmFpOjJxUERMWERhVTF4YTFFUlRiMVhLQmZQQ0IzbzJ3QTQ2cTQ5bmVpWFd3WSIsInNlcnZpY2UiOlt7ImlkIjoiZGlkOnBvbHlnb25pZDpwb2x5Z29uOm11bWJhaToycVBETFhEYVUxeGExRVJUYjFYS0JmUENCM28yd0E0NnE0OW5laVhXd1kjcHVzaCIsInR5cGUiOiJwdXNoLW5vdGlmaWNhdGlvbiIsInNlcnZpY2VFbmRwb2ludCI6Imh0dHBzOi8vcHVzaC1zdGFnaW5nLnBvbHlnb25pZC5jb20vYXBpL3YxIiwibWV0YWRhdGEiOnsiZGV2aWNlcyI6W3siY2lwaGVydGV4dCI6InhZK3RHWHUrOWlHMHZ6dFpMTTlKN25PcDNRbE1Uci85TmI3Qjl5Q0prbDlxcUpiZ1AvMExOL1VmTkxxQUk4RWZIcFhJVlVlTmVVUmNCNm82bWVMVlpJK2VvMlhvcDM2SE1iK2JyQnJTTjRqVHZWVkRDQXVXSkI2akV5Q3ZNRzlMaXp6blBsS3VQSE15dEdCVnZnV0laRFZBeVdZbTFyMk9PUzc4OU5DZm41MnNjV0VRVW5VRWdnTmpyWjlLdFpmb09RMlBDbUpqRXpDejg0ZUc3RGM2bEFvbi8ycTJJNVlLQk12RkhnT3c4N25wb0owczVrQ1RVVENjeVRlQmg2VXpLQk5aNElibndvR3ZYcG9FelBVZXZRdjRGbXVTaExYYVF3Vk9nalRBUXR0T2g2SjZhcmE4UHNndVFGQ3dNUTlxV2JjTjZYdXlScjk4TVlqbGxpL0VEN09TZzBsWVU5cUdLa1RaL2ZZN2VWZkYyeFFhOWZXK01WVzlxM2NJMjJzbkRwV28xY1ZYNWt1TWhpbmFsajZXV1Q0OTAvblNXak1rZ3JkL25CdXNiMHR4eG1jWDU3QUowcVlyMkNsK0pQb1FhcExiOEFTT3dGYU5kRDRZV3pKWXRXVmlDbktMZ3dQNDFHaGl5NVNWZE1vbU1sUy9kSGo2TVZPMjNyOVRiTDFrRy8rdkFIZWF0YkdvZ3p1OWd3SzlJckF3WS95THhMYVpQcHZzdlJLWjVBa2E1b1pkbmRNNkdLUkM0OVhoVXloQnNlY0N2Z1hNeGZGNVBnWGhROVFTb1drMzFXSWRiWG5vbmU2YmVNQkpLUVYzemg2MmpoZUFuV3czZW16dndKajRUUHU4WTJQZ2lDL3FaZXhlUVlKdFNkelJXZUFjK2N5a2ZwTXA0SmdrV2hBPSIsImFsZyI6IlJTQS1PQUVQLTUxMiJ9XX19XX0sIm1lc3NhZ2UiOm51bGwsInNjb3BlIjpbeyJpZCI6MjMsImNpcmN1aXRJZCI6ImNyZWRlbnRpYWxBdG9taWNRdWVyeU1UUFYyIiwicHJvb2YiOnsicGlfYSI6WyIyNjEwNjg1Nzc1MTY0Mzc0MDE2MTM5NDQwNTM4NzMxODI0NTgzNjQyODg0MTQxMzA5MTQwNDgzNDU0ODMzNzcyMjYxNDQ2NTI2NTEiLCIxNDE5MTI2MDA3MTY5NTk4MDAxMTY3OTUwMTgwODQ1MzIyMjI2NzUyMDcyMTc2Nzc1Nzc1OTE1MDEwMTk3NDM4MjA1MzE2MTY3NDYxMSIsIjEiXSwicGlfYiI6W1siNzY3MDg0Nzg0NDAxNTExNjk1NzUyNjE4MzcyODE5Njk3Nzk1NzMxMjYyNzMwNzc5NzkxOTU1NDEzNDY4NDkwMTQwMTQzNjAyMTk3NyIsIjE0OTU3ODQ1NDcyNjMwMDE3MDk1ODIxODMzMjIyNTgwMTk0MDYxMjY2MTg2ODUxNjM0MDUzODk3NzY4NzM4MjUzNjYzMjUzNjUwODM1Il0sWyIxNzgzNTY0MjQ1ODQ4NDYyODYyNzU1NjMyOTg3NjkxOTA3NzMzMzkxMjAxMTIzNTMwODc1ODgzMjE3Mjg4MDAxMjgxMzM5NzAyMjEwNCIsIjE4MTAwODYxMTMwMTQ5Njc4MTUzMTMzMDI1MDMxNzA5ODk3MTIwMDk3MDk4NTkxMjk4ODE3MzY3NDkxOTIwNTUzMDM3MDExNjUwMjI4Il0sWyIxIiwiMCJdXSwicGlfYyI6WyI2MjE3ODY1OTQ5Mjk5OTkwNjQyODMyNTIzMjU2ODYzMDQ4OTMyMjEwNTQ2MDQ5MjAzMTg5MTEzMzYyODUxNDc2OTY2ODI0MTYyMTkxIiwiMTkwMTY5NDkyMjUyNzc3NTU2OTAwMTk2NDczODU4NTU5MzY5Njk5Mjg5OTQyMTA5MDU5OTI2MjgzMDE5Njc4ODM4MDM2NzA0MzY1MTAiLCIxIl0sInByb3RvY29sIjoiZ3JvdGgxNiIsImN1cnZlIjoiYm4xMjgifSwicHViX3NpZ25hbHMiOlsiMSIsIjI3MTUyNjc2OTg3MTI4NTQyMDY2ODA4NTkxOTk4NTczMDAwMzcwNDM2NDY0NzIyNTE5NTEzMzQ4ODkxMDQ5NjQ0ODEzNzE4MDE4IiwiMjMiLCIyNzc1Mjc2NjgyMzM3MTQ3MTQwODI0ODIyNTcwODY4MTMxMzc2NDg2NjIzMTY1NTE4NzM2NjA3MTg4MTA3MDkxODk4NDQ3MTA0MiIsIjIxNTQ1NzY4ODgzNTA5NjU3MzQwMjA5MTcxNTQ5NDQxMDA1NjAzMzA2MDEyNTEzOTMyMjIxMzcxNTk5NTAxNDk4NTM0ODA3NzE5Njg5IiwiMSIsIjIxNTQ1NzY4ODgzNTA5NjU3MzQwMjA5MTcxNTQ5NDQxMDA1NjAzMzA2MDEyNTEzOTMyMjIxMzcxNTk5NTAxNDk4NTM0ODA3NzE5Njg5IiwiMTY3OTMyMzAzOCIsIjMzNjYxNTQyMzkwMDkxOTQ2NDE5MzA3NTU5Mjg1MDQ4MzcwNDYwMCIsIjAiLCIxNzAwMjQzNzExOTQzNDYxODc4MzU0NTY5NDYzMzAzODUzNzM4MDcyNjMzOTk5NDI0NDY4NDM0ODkxMzg0NDkyMzQyMjQ3MDgwNjg0NCIsIjAiLCI1IiwiODQwIiwiMTIwIiwiMzQwIiwiNTA5IiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIl19XX19.eyJwcm9vZiI6eyJwaV9hIjpbIjcwMjI2MTEzODk5MzY1MDEzNDI2NTkwMjQ2Njk0NTczNTA3OTUwMTU5ODkzOTI1NzAzMDMwODQ4MzcyMTQ4MDc1MzYyNDg4NTE5MzYiLCIxMzg1OTcwODc3NTU0Mzk0Mjk3MTYxNTcxNTA1MTczNjM4MTc4NTEzODkzMjQ3ODc1Mzg3MjU5MTU0NDQxODk1ODkwOTU2MDQyOTU3NCIsIjEiXSwicGlfYiI6W1siMTE1MzQ5NjMxNDgwODQ0OTk0NDg5MDc3NzQxMTMxNjg1OTEyNDYyMjQ4OTg0MTU4ODAwMzY5NTA1MDYyMjU0ODkyMDA1NTc2NTA2NjUiLCIxNDA3MjA4Mjk1MTQ0Njc5NDk5MDk4NDcwNTE3ODA1OTY2NjI4NzM1NTEwNjc5MzUwMTg5MTE2ODgwNjE2NjUwMTUxMDkzMDY0MzQ0MSJdLFsiNDY3ODgyNDc3ODQ5ODA0NzE2OTEzNTk2NTg3MTYwNDgzNjkwMTQ1NjI5MDQ0NjQ0NjUzMzEyNzUwOTU4Mzg5MDU5MDkzNTY5ODQxNCIsIjEyODE5NzMwNTMyMDg0MTM4NDI0ODQ0MjExNDg4NjcxMTUyNDgwOTU1MzQ0MTA2NzU4NTE3NDEzODAxOTIzNTM3OTU3MzYzOTgwMjA0Il0sWyIxIiwiMCJdXSwicGlfYyI6WyIxNTUyMDYzNjk4OTY2MTg3NzExNDUwNjkwNDgxMDQxMzExNDI4NzQ5ODE1OTk2NDA5OTU2MTY5ODUyNjc4MzUwMDE1NjU1MjQzMDAwNCIsIjEyNjkyNzA3NDA3MTczMDg0OTM5NzQ1ODU5NzE0ODMxNDYyMDQ1ODg5NDA4NTk4NTI3MjU0ODA3NzkwNDk0NDY2Mjc5Njg3ODU5MjQ3IiwiMSJdLCJwcm90b2NvbCI6Imdyb3RoMTYiLCJjdXJ2ZSI6ImJuMTI4In0sInB1Yl9zaWduYWxzIjpbIjI3MTUyNjc2OTg3MTI4NTQyMDY2ODA4NTkxOTk4NTczMDAwMzcwNDM2NDY0NzIyNTE5NTEzMzQ4ODkxMDQ5NjQ0ODEzNzE4MDE4IiwiMTIxODQ5NzQwNzE0Mjc3NjgzNTIwMjcwMDM4NzgzMTkzMzgyNDkzODM4NDYxNjQ3MzAyMDQ1MDUzMjY5NTM1NTA2NDczOTExNzg4MDAiLCI4NzU2MDYwMjA1MDg2ODAzMzM1MjUyMzE5NzQ4NzQ4MzU0NzYxOTYxODE0MDEyNzI1NDk5ODczMzgyOTg4MDU2NDE4NjgwNjI4NjE5Il19`
	authInstance, err := NewVerifier(verificationKeyloader, stateResolvers)
	require.NoError(t, err)
	_, err = authInstance.FullVerify(context.Background(), token, request, pubsignals.WithAcceptedProofGenerationDelay(proofGenerationDelay))
	require.Error(t, err, errors.New("no packer with profile which meets `accept` header requirements"))
}

func TestFullVerifier_OptionalFlags(t *testing.T) {
	verifierID := "did:iden3:polygon:amoy:xCRp75DgAdS63W65fmXHz6p9DwdonuRU9e46DifhX"
	callbackURL := "http://localhost:8080/callback?id=1234442-123123-123123"
	reason := "reason"
	message := "message"

	request := CreateAuthorizationRequestWithMessage(reason, message, verifierID, callbackURL)

	optTrue := true
	optFalse := false

	var mtpProofRequest1 protocol.ZeroKnowledgeProofRequest
	mtpProofRequest1.ID = 1
	mtpProofRequest1.CircuitID = "credentialAtomicQueryV3-beta.1"
	mtpProofRequest1.Optional = &optTrue
	mtpProofRequest1.Query = map[string]interface{}{
		"proofType":      "BJJSignature2021",
		"allowedIssuers": []string{"*"},
		"type":           "KYCAgeCredential",
		"context":        "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-nonmerklized.jsonld",
		"credentialSubject": map[string]interface{}{
			"documentType": map[string]interface{}{
				"$eq": 99,
			},
		},
	}

	// Second proof request (linked multi query with optional = false)
	var mtpProofRequest2 protocol.ZeroKnowledgeProofRequest
	mtpProofRequest2.ID = 2
	mtpProofRequest2.CircuitID = "linkedMultiQuery10-beta.1"
	mtpProofRequest2.Optional = &optFalse
	mtpProofRequest2.Query = map[string]interface{}{
		"groupId":        1,
		"proofType":      "Iden3SparseMerkleTreeProof",
		"allowedIssuers": []string{"*"},
		"type":           "KYCEmployee",
		"context":        "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v101.json-ld",
		"credentialSubject": map[string]interface{}{
			"documentType": map[string]interface{}{
				"$eq": 1,
			},
			"position": map[string]interface{}{
				"$eq": "boss",
				"$ne": "employee",
			},
		},
	}

	var mtpProofRequest3 protocol.ZeroKnowledgeProofRequest
	mtpProofRequest3.ID = 3
	mtpProofRequest3.CircuitID = "credentialAtomicQueryV3-beta.1"
	mtpProofRequest3.Optional = &optFalse
	mtpProofRequest3.Params = map[string]interface{}{
		"nullifierSessionId": "12345",
	}
	mtpProofRequest3.Query = map[string]interface{}{
		"groupId":        1,
		"proofType":      "BJJSignature2021",
		"allowedIssuers": []string{"*"},
		"type":           "KYCEmployee",
		"context":        "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v101.json-ld",
		"credentialSubject": map[string]interface{}{
			"hireDate": map[string]interface{}{
				"$eq": "2023-12-11",
			},
		},
	}

	request.Body.Scope = append(request.Body.Scope, mtpProofRequest1, mtpProofRequest2, mtpProofRequest3)

	schemaLoader := &mockJSONLDSchemaLoader{
		schemas: map[string]string{
			"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v101.json-ld": loadSchema("kyc-v101.json-ld"),
		},
	}

	authInstance, err := NewVerifier(verificationKeyloader, stateResolvers,
		WithDocumentLoader(schemaLoader))
	require.NoError(t, err)

	tokenString := "eyJhbGciOiJncm90aDE2IiwiY2lyY3VpdElkIjoiYXV0aFYyIiwiY3JpdCI6WyJjaXJjdWl0SWQiXSwidHlwIjoiYXBwbGljYXRpb24vaWRlbjMtemtwLWpzb24ifQ.eyJpZCI6ImIyZGY2MjYyLTM2ZTktNDgzYi1iZjNjLTRkZjUwYmRjZDE5MyIsInR5cCI6ImFwcGxpY2F0aW9uL2lkZW4zLXprcC1qc29uIiwidHlwZSI6Imh0dHBzOi8vaWRlbjMtY29tbXVuaWNhdGlvbi5pby9hdXRob3JpemF0aW9uLzEuMC9yZXNwb25zZSIsInRoaWQiOiIwOTRiM2ZjNS00YmNiLTQ2OTEtYWY3OS1jNWVmMDE5YTI1YWIiLCJib2R5Ijp7Im1lc3NhZ2UiOiJtZXNzYWdlIiwic2NvcGUiOlt7ImlkIjoyLCJjaXJjdWl0SWQiOiJsaW5rZWRNdWx0aVF1ZXJ5MTAtYmV0YS4xIiwicHJvb2YiOnsicGlfYSI6WyIxNTUxMDY1ODgzNDY0Njk3NDQyMzE3NTYzMTY0OTQ3MTg3ODU0NTIzMTYxNDUzMDA3NTYwOTI4NTU2MTczNDI5NDg1MDUzMzY1Njc0NCIsIjc0NTc2NTYyODQxODI1Mzk3MzgzNDQ2MDU3NjczMTkxNjc1NjA1NTk3MDg5NjUyMDI2MDk5MjkxNTE4MDA0MDkyNTQ3NDE1Njk0ODciLCIxIl0sInBpX2IiOltbIjEyNzQ2NTA4NDE0MzE2ODE0ODQyMDI3MDg2OTAyOTA4NTk4NTY3NTE2NTQ5NjE3MjM0NDMyOTA2OTE1NDM5MzEzMzk4MzM4NjQyODQwIiwiMTg2MDA5MDIyMjY5OTI0ODU0NTE5ODUxNzc3MDAxODQ4MDc3ODM5NTIwMzQwNTU0MzA2Njc0MDI5MzgxNjgyOTQyNDQwNzA4MjUzMjkiXSxbIjEyNzQ0MzgxNTg2OTkxMzQwNzIxNjAyODM5MjA2MTAzMzg4NjgxMjU1ODI4NzQyNzEzMDQyNTA2Mzc5MTA0MzA0MjA0OTA2NTQzOTAiLCIzMTA4ODQyNTgxOTYxOTA4MTk4MTYyMjE1MTE1MjQxOTcwMjU1MDI4NzM1NjQ5MjYyMDk4NDIyNTI4NDA5NDk1MjY1MjQ1MjE0ODEyIl0sWyIxIiwiMCJdXSwicGlfYyI6WyI4MjQ5ODYxNzkwNTEyNzg0NDQyMTA2ODg1OTA2NDc4NDI2NjY5MTU2NjU1OTcxNDc2MzIzMzcwNTMzNTEyNzcxMTA4ODE3MTU5NjA0IiwiMTMyODM4NDMzMTExOTcxNzg5NDc2MDQ1NzQ1NTQzODE4NTUzOTUzNTg1NzcxMjYyMzAyODg0NTk5NDUxMjkwNTY5OTcwNzMxOTgxOTgiLCIxIl0sInByb3RvY29sIjoiZ3JvdGgxNiIsImN1cnZlIjoiYm4xMjgifSwicHViX3NpZ25hbHMiOlsiNTAwOTg5MTMxMjg0MDA2NzI0ODkwOTk4NjUzOTYxODg4NzAwNjQ0Njg2MzE2NTY2MzI5ODE3NDQ0NTQ3ODQ4OTUwNDgwNzQ2NjgxNiIsIjEiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMTU1NzcxMTQ3OTkwNTY5Mzk2MzM1NTI4NDU1MzEwMTEwMjQ2NzI5Mzk0OTM0OTI3Njk2MjgyODU2NjEzNTk3MTE2NTUyMTQ1NjExNjIiLCIxNjk5ODc2Mjk2NTM5Njk0NDc4MjY2NzU1Nzc0MTE4NTgyODEzNjQ2Nzc0Nzc2MjgzMDAyODIxNzAyNzk3MzYxNzM3Mzg2MjMwMTk1OCIsIjkzMDI1MjYyMDg1MDc3NTM3OTk1MDExMzAxMjg5MDg0OTQ2NzM0MTI0NDM2MzE1NDE0MjQ0MDk1NTEyMDUyNzc1Mjk5NDk2NjIzOTQiLCIxNDYxMjUxODAwNjQ5Mzk5ODAzNzE0OTI5OTY0Nzk3NDIzNzc3MTU1MTA3MDMxMjA5Njg4MjQwNzQ0MDY1MTA1Mjc1MjI1OTAzODQwMyIsIjE0NjEyNTE4MDA2NDkzOTk4MDM3MTQ5Mjk5NjQ3OTc0MjM3NzcxNTUxMDcwMzEyMDk2ODgyNDA3NDQwNjUxMDUyNzUyMjU5MDM4NDAzIiwiMTQ2MTI1MTgwMDY0OTM5OTgwMzcxNDkyOTk2NDc5NzQyMzc3NzE1NTEwNzAzMTIwOTY4ODI0MDc0NDA2NTEwNTI3NTIyNTkwMzg0MDMiLCIxNDYxMjUxODAwNjQ5Mzk5ODAzNzE0OTI5OTY0Nzk3NDIzNzc3MTU1MTA3MDMxMjA5Njg4MjQwNzQ0MDY1MTA1Mjc1MjI1OTAzODQwMyIsIjE0NjEyNTE4MDA2NDkzOTk4MDM3MTQ5Mjk5NjQ3OTc0MjM3NzcxNTUxMDcwMzEyMDk2ODgyNDA3NDQwNjUxMDUyNzUyMjU5MDM4NDAzIiwiMTQ2MTI1MTgwMDY0OTM5OTgwMzcxNDkyOTk2NDc5NzQyMzc3NzE1NTEwNzAzMTIwOTY4ODI0MDc0NDA2NTEwNTI3NTIyNTkwMzg0MDMiLCIxNDYxMjUxODAwNjQ5Mzk5ODAzNzE0OTI5OTY0Nzk3NDIzNzc3MTU1MTA3MDMxMjA5Njg4MjQwNzQ0MDY1MTA1Mjc1MjI1OTAzODQwMyJdfSx7ImlkIjozLCJjaXJjdWl0SWQiOiJjcmVkZW50aWFsQXRvbWljUXVlcnlWMy1iZXRhLjEiLCJwcm9vZiI6eyJwaV9hIjpbIjEyMjAwOTE0OTY1NjE3Mjk4NDUwMTI3MzY0OTA3Njk5MjE1NzM1MjYzMDAxMTE4MzY4MDUzMzQ0OTg1MzQ4NDU5NTg5OTkwMDQ0MDE3IiwiMTk0MzI4MDMzNzk4MDg4NDgxOTk4MjE2OTEwNDgzNzE4NDEyMzMyMzc4OTA2ODMyNzM3ODgyNjc0OTY2NTg0NDI1ODg1OTk0NjMxNzYiLCIxIl0sInBpX2IiOltbIjk0MzA2ODQxMDY5NTMwMzQ4OTk0ODQ3ODQzNDE5NDcyMTc4OTU2ODk2NjQwMDQ2MTI5MzU1MTIxMTY0NzQwNTUxMDI3MTc3MzAyMTUiLCIxMDI4NDQxNTM2MDg3NDQzMjgxNjM4MjEyNjk0MDA0MjYxNjIxNTkzMzMwMjg2OTI1NDk5OTcyMDA1NTg0NDk0ODkwNDMyMTc5NDIwIl0sWyIyNTk3NDE5OTg5MTk3NDA2NTQ5NDQ1ODY1MTg3MTg0MjE2ODE1OTU5MDE4ODYxMzUyMDQ2MzAxNzAzMTYzNjAwODYxNTI3NjYzMjc4IiwiMTYzODU5MDk5MjcyOTUwODEwMjY4NjYyNjI0Nzk3NzQ0NTg4MDEzMTU1NzYxNTI1MTgzOTQzNzk0NjExODAxODg3MzQyODQyNjM4NjkiXSxbIjEiLCIwIl1dLCJwaV9jIjpbIjU3NTY2Nzc5MzE2ODU2NTY1ODUwNzA5OTg3MjM3NTIzNTY5OTEzNjQyMzAxODA0Nzg5NDU0NzQ5ODIyNjg5NTM0Nzk4MDA1MjQyMDciLCIyMDMwNzY5NTk1MTcwODc3MTk2MjIxNzYxMjc2MjM2NzY3ODgzNjg1OTg0OTYwNTY2OTgzODUxMDUxMTg5MjM5MDQ3NTkyMzk4OTk2OSIsIjEiXSwicHJvdG9jb2wiOiJncm90aDE2IiwiY3VydmUiOiJibjEyOCJ9LCJwdWJfc2lnbmFscyI6WyIxIiwiMjE1NzUxMjcyMTYyMzYyNDg4Njk3MDIyNzYyNDYwMzc1NTcxMTkwMDc0NjYxODAzMDE5NTc3NjIxOTY1OTM3ODY3MzMwMDc2MTciLCI0NDg3Mzg2MzMyNDc5NDg5MTU4MDAzNTk3ODQ0OTkwNDg3OTg0OTI1NDcxODEzOTA3NDYyNDgzOTA3MDU0NDI1NzU5NTY0MTc1MzQxIiwiNTAwOTg5MTMxMjg0MDA2NzI0ODkwOTk4NjUzOTYxODg4NzAwNjQ0Njg2MzE2NTY2MzI5ODE3NDQ0NTQ3ODQ4OTUwNDgwNzQ2NjgxNiIsIjUxMTMxMTA3NDIxNjM1NjExNjE2ODExMTA2MDA4NTgwMTg4ODY0NDAyOTEyODg5NjI2ODEyMzM0Mjk5NzUxMzM5MTYzNDg2MDY1MjEiLCIwIiwiMSIsIjMiLCIyNTE5ODU0MzM4MTIwMDY2NTc3MDgwNTgxNjA0NjI3MTU5NDg4NTYwNDAwMjQ0NTEwNTc2NzY1MzYxNjg3ODE2NzgyNjg5NTYxNyIsIjEiLCI0NDg3Mzg2MzMyNDc5NDg5MTU4MDAzNTk3ODQ0OTkwNDg3OTg0OTI1NDcxODEzOTA3NDYyNDgzOTA3MDU0NDI1NzU5NTY0MTc1MzQxIiwiMTc1MzM1NTM5NyIsIjIxOTU3ODYxNzA2NDU0MDAxNjIzNDE2MTY0MDM3NTc1NTg2NTQxMiIsIjEyOTYzNTE3NTgyNjkwNjExNzMzMTcxMDUwNDE5NjgwNjcwNzc0NTE5MTQzODYwODYyMjI5MzE1MTYxOTkxOTQ5NTk4Njk0NjM4ODIiLCIwIiwiMSIsIjE3MDIyNTI4MDAwMDAwMDAwMDAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIxIiwiMjUxOTg1NDMzODEyMDA2NjU3NzA4MDU4MTYwNDYyNzE1OTQ4ODU2MDQwMDI0NDUxMDU3Njc2NTM2MTY4NzgxNjc4MjY4OTU2MTciLCIxMjM0NSJdfV19LCJmcm9tIjoiZGlkOmlkZW4zOnBvbHlnb246YW1veTp4N1o5NVZrVXV5bzZtcXJhSncyVkd3Q2ZxVHpkcWhNMVJWalJIemNwSyIsInRvIjoiZGlkOmlkZW4zOnBvbHlnb246YW1veTp4Q1JwNzVEZ0FkUzYzVzY1Zm1YSHo2cDlEd2RvbnVSVTllNDZEaWZoWCJ9.eyJwcm9vZiI6eyJwaV9hIjpbIjE0ODA1MzI2NDU2MzIzOTAzOTA1MDk1NjczMDk0NDMzMzQzMTEzNTE1NDY0OTkxMzU4OTk1ODY5MjY2MDI1MTg1NTMyNjEzMTQ3NDA1IiwiMTIwNzkwNTA2MjM0MzM0NTMyODE5MzI3MjMyMTExNjc0NjM2MDQwNDMzMzE5NTMxMDcwNDY1NDM3NTkxMDg4MDIyNjQ4NjY4NTc1ODAiLCIxIl0sInBpX2IiOltbIjM1NjIyODQ1MjI3MDUzNTA1OTA3Mzk2OTI2MzI3MTM3NjY2MjAzNjc3MzAxMDQzMzM0ODMzNzIzMjYxNjQwMjM0NDQyNTE2MTkwMzMiLCIyMDU1MTU4MDg5NTQyMTgyODQ0NjQ2MzczODU2Nzk1MTE5NDkxNTgyNzM3NjEzNjczNDE1MDQwMTkzNjMxMzQxNjIwMzAwOTYwMTA4MyJdLFsiMTYyMjEyMzExMjgxNTg1MzQ5NDY2MDQ4NDAxMDI4Njg2OTYxNzIwNDY3NTk4OTkyNTczNDE1MjIzMjMzNjcwMTEwNTIxOTIzOTEzNjkiLCIyMTQ5NzI5NDAyNzE2OTc1MDY5NzA2Njk4MTcyMzczNDc1ODk0MzczNzY1NDA4MDMyODQ3NzAzNDQ1OTQ4NjYwNzYxNTY1MzY2Njk5OSJdLFsiMSIsIjAiXV0sInBpX2MiOlsiODYyMzEzMjQxNzI4MjE3NzUwNTY1MDg4MDYzMTE0OTg4Nzc0Mzg1ODkyMzkyMjI5NzY1NDExMTAxMzEyMDM0MTg4ODUwMzE0MDU3MCIsIjU1NzAzMzk0NjgzNjk3Njg4MjkxMjMzNTAzNTA2ODE5OTEyMTkxMzk3MjMxMDY3MTYwODQwODMzNDIzMTc3Mzg5NzUzOTMwNzM2NzciLCIxIl0sInByb3RvY29sIjoiZ3JvdGgxNiIsImN1cnZlIjoiYm4xMjgifSwicHViX3NpZ25hbHMiOlsiMjE1NzUxMjcyMTYyMzYyNDg4Njk3MDIyNzYyNDYwMzc1NTcxMTkwMDc0NjYxODAzMDE5NTc3NjIxOTY1OTM3ODY3MzMwMDc2MTciLCIyMTU1OTkxMjE3NjQ3NjY0NTQ4MjQ3MjE4Mjc0ODgyMDY4MzcwOTM5NTk3Nzc0NDU3MzY3MTIzNDg2NjM1ODIxOTE3NDUxODQyNDQyMCIsIjE3ODQ5OTgxNzIwNjM0MjEyODAyNjY0MTg5OTI5NjcxMTQwNzYyNTU3NDgzMjM2NzA4MDk3NzIzODg0MTcyNjQxMTI0NjkxMjIyMjk4Il19"

	returnMsg, err := authInstance.FullVerify(context.Background(), tokenString, request, pubsignals.WithAcceptedProofGenerationDelay(proofGenerationDelay))
	require.NoError(t, err)
	require.NotNil(t, returnMsg)
	schemaLoader.assert(t)
}
