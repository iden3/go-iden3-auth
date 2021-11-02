package packer

import (
	"github.com/iden3/go-auth/pkg/communication/auth"
	"github.com/iden3/go-auth/pkg/types"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestPlainMessagePacker_Pack(t *testing.T) {
	packer := PlainMessagePacker{}

	var message types.AuthorizationMessageRequest
	message.Type = auth.AuthorizationRequestMessageType
	message.Data = types.AuthorizationMessageRequestData{}
	message.Data.Audience = "1125GJqgw6YEsKFwj63GY87MMxPL9kwDKxPUiwMLNZ"
	message.Data.CallbackURL = "https://test.com"

	zkpProofRequest := types.ZeroKnowledgeProofRequest{
		Type:      types.ZeroKnowledgeProofType,
		CircuitID: types.KycBySignaturesCircuitID,
		Rules: map[string]interface{}{
			"challenge": "1234567",
		},
	}
	message.Data.Scope = []types.TypedScope{zkpProofRequest}
	msgBytes, err := packer.Pack("application/json", &message)
	assert.Nil(t, err)
	assert.NotEmpty(t, msgBytes)
	m, err := packer.Unpack(msgBytes)
	assert.Nil(t, err)
	assert.NotEmpty(t, m)

}
func TestPlainMessagePacker_Unpack(t *testing.T) {
	packer := PlainMessagePacker{}

	msgBytes := []byte(`{"type":"https://iden3-communication.io/authorization-request/v1","data":{"callbackUrl":"https://test.com","audience":"1125GJqgw6YEsKFwj63GY87MMxPL9kwDKxPUiwMLNZ","scope":[{"circuit_id":"kycBySignatures","type":"zeroknowledge","rules":{"challenge":"1234567"}}]}}`)
	message, err := packer.Unpack(msgBytes)
	assert.Nil(t, err)
	assert.Equal(t, auth.AuthorizationRequestMessageType, message.GetType())

}
