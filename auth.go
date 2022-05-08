package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/iden3/go-circuits"
	"github.com/iden3/go-iden3-auth/proofs"
	"github.com/iden3/go-iden3-auth/verification/pubsignals"
	"github.com/iden3/iden3comm/protocol"
	"github.com/iden3/jwz"
	"github.com/pkg/errors"
)

// CreateAuthorizationRequest creates new authorization request message
func CreateAuthorizationRequest(challenge string, aud, callbackURL string) *protocol.AuthorizationRequestMessage {
	var message protocol.AuthorizationRequestMessage

	message.Type = protocol.AuthorizationRequestMessageType
	message.ThreadID = challenge
	message.Body = protocol.AuthorizationRequestMessageBody{
		CallbackURL: callbackURL,
		Audience:    aud,
		Scope:       []protocol.ZeroKnowledgeProofRequest{},
	}

	return &message
}

// Verify performs verification of auth response based on auth request
func Verify(ctx context.Context, response protocol.AuthorizationResponseMessage, request protocol.AuthorizationRequestMessage, opts pubsignals.VerificationOptions) (err error) {

	for _, proofRequest := range request.Body.Scope {
		proofResponse := findProofByRequestId(response.Body.Scope, proofRequest.ID)
		if proofResponse == nil {
			return errors.Errorf("proof for request id %s is presented not found", proofRequest.ID)
		}
		if proofRequest.CircuitID != proofResponse.CircuitID {
			return errors.Errorf("proof response for request id %s has different circuit id than requested. requested %s - presented %s", proofRequest.ID, proofRequest.CircuitID, proofResponse.CircuitID)
		}
		err = proofs.VerifyProof(*proofResponse)
		if err != nil {
			return errors.Wrap(err, fmt.Sprintf("proof with request id %s and circuit id %s is not valid", proofRequest.ID, proofRequest.CircuitID))
		}
		cv, err := getCircuitVerifier(circuits.CircuitID(proofResponse.CircuitID), proofResponse.PubSignals)
		if err != nil {
			return errors.Wrap(err, fmt.Sprintf("circuit with id %s is not supported by library", proofRequest.CircuitID))
		}
		err = cv.VerifyStates(ctx, opts)
		if err != nil {
			return err
		}
		err = cv.VerifyQuery(ctx, proofRequest.Rules["query"].(pubsignals.Query))
		if err != nil {
			return err
		}
	}

	return nil
}

// VerifyJWZ performs verification of jwz token
func VerifyJWZ(ctx context.Context, token string, options pubsignals.VerificationOptions) (t *jwz.Token, err error) {

	t, err = jwz.Parse(token)
	if err != nil {
		return nil, err
	}
	verificationKey, err := circuits.GetVerificationKey(circuits.CircuitID(t.CircuitID))
	if err != nil {
		return nil, err
	}
	err = t.Verify(verificationKey)
	if err != nil {
		return nil, err
	}

	cv, err := getCircuitVerifier(circuits.CircuitID(t.CircuitID), t.ZkProof.PubSignals)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprintf("circuit with id %s is not supported by library", t.CircuitID))
	}
	err = cv.VerifyStates(ctx, options)
	if err != nil {
		return nil, err
	}

	return
}

// FullVerify performs verification of jwz token and auth request
func FullVerify(ctx context.Context, token string, request protocol.AuthorizationRequestMessage, options pubsignals.VerificationOptions) error {

	// verify jwz
	t, err := VerifyJWZ(ctx, token, options)

	if err != nil {
		return err
	}

	// parse jwz paylaod as json message
	var authMsgResponse protocol.AuthorizationResponseMessage
	msg := t.GetPayload()
	err = json.Unmarshal(msg, &authMsgResponse)
	if err != nil {
		return err
	}

	// verify proof requests

	err = Verify(ctx, authMsgResponse, request, options)
	return err
}

func getCircuitVerifier(circuitID circuits.CircuitID, signals []string) (pubsignals.Verifier, error) {
	pubSignalBytes, err := json.Marshal(signals)
	if err != nil {
		return nil, err
	}
	var cv pubsignals.Verifier
	switch circuitID {
	case circuits.AtomicQueryMTPCircuitID:
		cv = &pubsignals.AtomicQueryMTP{}
	case circuits.AuthCircuitID:
		cv = &pubsignals.Auth{}
	}
	err = cv.PubSignalsUnmarshal(pubSignalBytes)
	if err != nil {
		return nil, err
	}
	return cv, nil
}
func findProofByRequestId(proofs []protocol.ZeroKnowledgeProofResponse, id string) *protocol.ZeroKnowledgeProofResponse {
	for _, respProof := range proofs {
		if respProof.ID == id {
			return &respProof
		}
	}
	return nil
}
