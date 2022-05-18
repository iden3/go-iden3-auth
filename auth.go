package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/iden3/go-circuits"
	"github.com/iden3/go-iden3-auth/proofs"
	"github.com/iden3/go-iden3-auth/pubsignals"
	"github.com/iden3/go-iden3-auth/state"
	"github.com/iden3/go-jwz"
	"github.com/iden3/iden3comm/packers"
	"github.com/iden3/iden3comm/protocol"
	"github.com/pkg/errors"
	"math/big"
	"strconv"
	"time"
)

// Verifier is a struct for auth instance
type Verifier struct {
	circuitsVerificationKeys map[circuits.CircuitID][]byte
}

// NewVerifier returns setup instance of auth library
func NewVerifier(keys map[circuits.CircuitID][]byte) *Verifier {
	return &Verifier{circuitsVerificationKeys: keys}
}

// CreateAuthorizationRequest creates new authorization request message
// sender - client identifier
// challenge - int64 that will represent unique message id and provide correlation with response
func CreateAuthorizationRequest(challenge int64, sender, callbackURL string) *protocol.AuthorizationRequestMessage {
	var message protocol.AuthorizationRequestMessage

	message.Typ = packers.MediaTypePlainMessage
	message.Type = protocol.AuthorizationRequestMessageType
	message.ID = strconv.FormatInt(challenge, 10)

	message.ThreadID = strconv.FormatInt(challenge, 10)
	message.Body = protocol.AuthorizationRequestMessageBody{
		CallbackURL: callbackURL,
		Scope:       []protocol.ZeroKnowledgeProofRequest{},
	}
	message.From = sender

	return &message
}

// VerifyAuthResponse performs verification of auth response based on auth request
func (v *Verifier) VerifyAuthResponse(ctx context.Context, response protocol.AuthorizationResponseMessage, request protocol.AuthorizationRequestMessage, opts state.VerificationOptions) (err error) {

	for _, proofRequest := range request.Body.Scope {
		proofResponse := findProofByRequestID(response.Body.Scope, proofRequest.ID)
		if proofResponse == nil {
			return errors.Errorf("proof for request id %s is presented not found", proofRequest.ID)
		}
		if proofRequest.CircuitID != proofResponse.CircuitID {
			return errors.Errorf("proof response for request id %s has different circuit id than requested. requested %s - presented %s", proofRequest.ID, proofRequest.CircuitID, proofResponse.CircuitID)
		}

		verificationKey, ok := v.circuitsVerificationKeys[circuits.CircuitID(proofRequest.CircuitID)]
		if !ok {
			return errors.Errorf("verification key for circuit with id %s not found", proofRequest.CircuitID)
		}
		err = proofs.VerifyProof(*proofResponse, verificationKey)
		if err != nil {
			return errors.Wrap(err, fmt.Sprintf("proof with request id %s and circuit id %s is not valid", proofRequest.ID, proofRequest.CircuitID))
		}

		cv, err := getPublicSignalsVerifier(circuits.CircuitID(proofResponse.CircuitID), proofResponse.PubSignals)
		if err != nil {
			return errors.Wrap(err, fmt.Sprintf("circuit with id %s is not supported by library", proofRequest.CircuitID))
		}

		//err = cv.VerifyQuery(ctx, proofRequest.Rules["query"].(pubsignals.Query))
		//if err != nil {
		//	return err
		//}

		err = cv.VerifyStates(ctx, opts)
		if err != nil {
			return err
		}
	}

	return nil
}

// VerifyJWZ performs verification of jwz token
func (v *Verifier) VerifyJWZ(ctx context.Context, token string, options state.VerificationOptions) (t *jwz.Token, err error) {

	t, err = jwz.Parse(token)
	if err != nil {
		return nil, err
	}

	verificationKey, ok := v.circuitsVerificationKeys[circuits.CircuitID(t.CircuitID)]
	if !ok {
		return nil, errors.Errorf("verification key for circuit with id %s not found", t.CircuitID)
	}
	_, err = t.Verify(verificationKey)
	if err != nil {
		return nil, err
	}

	circuitVerifier, err := getPublicSignalsVerifier(circuits.CircuitID(t.CircuitID), t.ZkProof.PubSignals)
	if err != nil {
		return nil, err
	}

	err = circuitVerifier.VerifyStates(ctx, options)
	if err != nil {
		return nil, err
	}

	return
}

// FullVerify performs verification of jwz token and auth request
func (v *Verifier) FullVerify(ctx context.Context, token string, request protocol.AuthorizationRequestMessage, options state.VerificationOptions) error {

	//// verify jwz
	t, err := v.VerifyJWZ(ctx, token, options)
	if err != nil {
		return err
	}

	// parse jwz payload as json message
	var authMsgResponse protocol.AuthorizationResponseMessage
	msg := t.GetPayload()
	err = json.Unmarshal(msg, &authMsgResponse)
	if err != nil {
		return err
	}

	// verify proof requests
	err = v.VerifyAuthResponse(ctx, authMsgResponse, request, options)
	return err
}

// VerifyState allows to verify state
func VerifyState(ctx context.Context, id, s *big.Int, opts state.ExtendedVerificationsOptions) error {

	client, err := ethclient.Dial(opts.RPCUrl)
	if err != nil {
		return err
	}
	stateVerificationRes, err := state.Resolve(ctx, client, opts.Contract, id, s)
	if err != nil {
		return err
	}
	// VerifyStates performs all state verifications
	if !stateVerificationRes.Latest {
		if opts.OnlyLatestStates {
			return errors.New("state is not latest")
		}
		transitionTime := time.Unix(stateVerificationRes.TransitionTimestamp, 0)
		if time.Now().Sub(transitionTime) > opts.AcceptedStateTransitionDelay {
			return errors.New("state is not latest and lost actuality")
		}
	}

	return nil

}

func getPublicSignalsVerifier(circuitID circuits.CircuitID, signals []string) (pubsignals.Verifier, error) {
	pubSignalBytes, err := json.Marshal(signals)
	if err != nil {
		return nil, err
	}

	cv, err := pubsignals.GetVerifier(circuitID)
	if err != nil {
		return nil, err
	}

	err = cv.PubSignalsUnmarshal(pubSignalBytes)
	if err != nil {
		return nil, err
	}
	return cv, nil
}
func findProofByRequestID(arr []protocol.ZeroKnowledgeProofResponse, id string) *protocol.ZeroKnowledgeProofResponse {
	for _, respProof := range arr {
		if respProof.ID == id {
			return &respProof
		}
	}
	return nil
}
