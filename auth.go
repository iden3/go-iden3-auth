package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/google/uuid"
	"github.com/iden3/contracts-abi/state/go/abi"
	"github.com/iden3/go-circuits/v2"
	"github.com/iden3/go-iden3-auth/v2/loaders"
	"github.com/iden3/go-iden3-auth/v2/proofs"
	"github.com/iden3/go-iden3-auth/v2/pubsignals"
	"github.com/iden3/go-iden3-auth/v2/state"
	"github.com/iden3/go-jwz/v2"
	"github.com/iden3/iden3comm/v2/packers"
	"github.com/iden3/iden3comm/v2/protocol"
	"github.com/pkg/errors"
)

// Verifier is a struct for auth instance
type Verifier struct {
	verificationKeyLoader loaders.VerificationKeyLoader
	claimSchemaLoader     loaders.SchemaLoader
	stateResolver         map[string]pubsignals.StateResolver
}

// NewVerifier returns setup instance of auth library
func NewVerifier(
	keyLoader loaders.VerificationKeyLoader,
	claimSchemaLoader loaders.SchemaLoader,
	resolver map[string]pubsignals.StateResolver) *Verifier {

	return &Verifier{
		verificationKeyLoader: keyLoader,
		claimSchemaLoader:     claimSchemaLoader,
		stateResolver:         resolver,
	}
}

// CreateAuthorizationRequest creates new authorization request message
// sender - client identifier
// reason - describes purpose of request
// callbackURL - url for authorization response
func CreateAuthorizationRequest(reason, sender, callbackURL string) protocol.AuthorizationRequestMessage {
	return CreateAuthorizationRequestWithMessage(reason, "", sender, callbackURL)
}

// CreateAuthorizationRequestWithMessage creates new authorization request with message for signing with jwz
func CreateAuthorizationRequestWithMessage(reason, message, sender,
	callbackURL string) protocol.AuthorizationRequestMessage {
	var request protocol.AuthorizationRequestMessage

	request.Typ = packers.MediaTypePlainMessage
	request.Type = protocol.AuthorizationRequestMessageType
	request.ID = uuid.New().String()
	request.ThreadID = request.ID
	request.Body = protocol.AuthorizationRequestMessageBody{
		CallbackURL: callbackURL,
		Reason:      reason,
		Message:     message,
		Scope:       []protocol.ZeroKnowledgeProofRequest{},
	}
	request.From = sender

	return request
}

// VerifyAuthResponse performs verification of auth response based on auth request
func (v *Verifier) VerifyAuthResponse(
	ctx context.Context,
	response protocol.AuthorizationResponseMessage,
	request protocol.AuthorizationRequestMessage,
	opts ...pubsignals.VerifyOpt,
) error {

	if request.Body.Message != response.Body.Message {
		return errors.Errorf("message for request id %v was not presented in the response", request.ID)
	}

	for _, proofRequest := range request.Body.Scope {
		proofResponse := findProofByRequestID(response.Body.Scope, proofRequest.ID)
		if proofResponse == nil {
			return errors.Errorf("proof for zk request id %v is presented not found", proofRequest.ID)
		}
		if proofRequest.CircuitID != proofResponse.CircuitID {
			return errors.Errorf("proof response for request id %v has different circuit id than requested. requested %s - presented %s", proofRequest.ID, proofRequest.CircuitID, proofResponse.CircuitID)
		}

		verificationKey, err := v.verificationKeyLoader.Load(circuits.CircuitID(proofResponse.CircuitID))
		if err != nil {
			return err
		}
		err = proofs.VerifyProof(*proofResponse, verificationKey)
		if err != nil {
			return errors.Wrap(err, fmt.Sprintf("proof with request id %v and circuit id %s is not valid", proofRequest.ID, proofRequest.CircuitID))
		}

		cv, err := getPublicSignalsVerifier(circuits.CircuitID(proofResponse.CircuitID), proofResponse.PubSignals)
		if err != nil {
			return errors.Wrap(err, fmt.Sprintf("circuit with id %s is not supported by library", proofRequest.CircuitID))
		}

		// prepare query from request
		queryBytes, err := json.Marshal(proofRequest.Query)
		if err != nil {
			return err
		}
		var query pubsignals.Query
		err = json.Unmarshal(queryBytes, &query)
		if err != nil {
			return err
		}

		// verify proof author

		err = cv.VerifyIDOwnership(response.From, big.NewInt(int64(proofResponse.ID)))
		if err != nil {
			return err
		}

		rawMessage, err := proofResponse.VerifiablePresentation.MarshalJSON()
		if err != nil {
			return errors.Errorf("failed get VerifiablePresentation: %v", err)
		}
		if string(rawMessage) == "null" {
			rawMessage = nil
		}

		err = cv.VerifyQuery(ctx, query, v.claimSchemaLoader, rawMessage)
		if err != nil {
			return err
		}

		err = cv.VerifyStates(ctx, v.stateResolver, opts...)
		if err != nil {
			return err
		}
	}

	return nil
}

// VerifyJWZ performs verification of jwz token
func (v *Verifier) VerifyJWZ(
	ctx context.Context,
	token string,
	opts ...pubsignals.VerifyOpt,
) (t *jwz.Token, err error) {

	t, err = jwz.Parse(token)
	if err != nil {
		return nil, err
	}

	verificationKey, err := v.verificationKeyLoader.Load(circuits.CircuitID(t.CircuitID))
	if err != nil {
		return nil, errors.Errorf("verification key for circuit with id %s not found", t.CircuitID)
	}
	isValid, err := t.Verify(verificationKey)
	if err != nil {
		return nil, err
	}
	if !isValid {
		return nil, errors.New("zero knowledge proof of jwz is not valid")
	}

	circuitVerifier, err := getPublicSignalsVerifier(circuits.CircuitID(t.CircuitID), t.ZkProof.PubSignals)
	if err != nil {
		return nil, err
	}

	err = circuitVerifier.VerifyStates(ctx, v.stateResolver, opts...)
	if err != nil {
		return nil, err
	}

	return t, err
}

// FullVerify performs verification of jwz token and auth request
func (v *Verifier) FullVerify(
	ctx context.Context,
	token string,
	request protocol.AuthorizationRequestMessage,
	opts ...pubsignals.VerifyOpt, // TODO(illia-korotia): is ok have common option for VerifyJWZ and VerifyAuthResponse?
) (*protocol.AuthorizationResponseMessage, error) {

	t, err := v.VerifyJWZ(ctx, token, opts...)
	if err != nil {
		return nil, err
	}
	// parse jwz payload as json message
	var authMsgResponse protocol.AuthorizationResponseMessage
	msg := t.GetPayload()
	err = json.Unmarshal(msg, &authMsgResponse)
	if err != nil {
		return nil, err
	}

	circuitVerifier, err := getPublicSignalsVerifier(circuits.CircuitID(t.CircuitID), t.ZkProof.PubSignals)
	if err != nil {
		return nil, err
	}

	challengeBytes, err := t.GetMessageHash()
	if err != nil {
		return nil, err
	}

	err = circuitVerifier.VerifyIDOwnership(authMsgResponse.From, new(big.Int).SetBytes(challengeBytes))
	if err != nil {
		return &authMsgResponse, err
	}

	err = v.VerifyAuthResponse(ctx, authMsgResponse, request, opts...)
	return &authMsgResponse, err
}

// VerifyState allows to verify state without binding to  verifier instance
func VerifyState(ctx context.Context, id, s *big.Int, opts state.ExtendedVerificationsOptions) error {

	client, err := ethclient.Dial(opts.RPCUrl)
	if err != nil {
		return err
	}
	stateGetter, err := abi.NewStateCaller(common.HexToAddress(opts.Contract), client)
	if err != nil {
		return err
	}
	stateVerificationRes, err := state.Resolve(ctx, stateGetter, id, s)
	if err != nil {
		return err
	}
	// VerifyStates performs all state verifications
	if !stateVerificationRes.Latest {
		if opts.OnlyLatestStates {
			return errors.New("state is not latest")
		}
		transitionTime := time.Unix(stateVerificationRes.TransitionTimestamp, 0)
		if time.Since(transitionTime) > opts.AcceptedStateTransitionDelay {
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
func findProofByRequestID(arr []protocol.ZeroKnowledgeProofResponse, id uint32) *protocol.ZeroKnowledgeProofResponse {
	for _, respProof := range arr {
		if respProof.ID == id {
			return &respProof
		}
	}
	return nil
}
