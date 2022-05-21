package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/gofrs/uuid"
	"github.com/iden3/go-circuits"
	"github.com/iden3/go-iden3-auth/proofs"
	"github.com/iden3/go-iden3-auth/pubsignals"
	"github.com/iden3/go-iden3-auth/state"
	"github.com/iden3/go-jwz"
	"github.com/iden3/iden3comm/packers"
	"github.com/iden3/iden3comm/protocol"
	"github.com/pkg/errors"
	"math/big"
	"time"
)

// Verifier is a struct for auth instance
type Verifier struct {
	verificationKeyLoader VerificationKeyLoader
	opts                  state.VerificationOptions
}

// VerificationKeyLoader load verification key bytes for specific circuit
type VerificationKeyLoader interface {
	Load(id circuits.CircuitID) ([]byte, error)
}

// NewVerifier returns setup instance of auth library
func NewVerifier(keyLoader VerificationKeyLoader, opts state.VerificationOptions) *Verifier {
	return &Verifier{verificationKeyLoader: keyLoader, opts: opts}
}

// CreateAuthorizationRequest creates new authorization request message
// sender - client identifier
// reason - describes purpose of request
// callbackURL - url for authorization response
func CreateAuthorizationRequest(reason, sender, callbackURL string) (*protocol.AuthorizationRequestMessage, error) {
	return CreateAuthorizationRequestWithMessage(reason, "", sender, callbackURL)
}

// CreateAuthorizationRequestWithMessage creates new authorization request with message for signing with jwz
func CreateAuthorizationRequestWithMessage(reason, message, sender, callbackURL string) (*protocol.AuthorizationRequestMessage, error) {
	var request protocol.AuthorizationRequestMessage

	id, err := uuid.NewV4()
	if err != nil {
		return nil, err
	}

	request.Typ = packers.MediaTypePlainMessage
	request.Type = protocol.AuthorizationRequestMessageType
	request.ID = id.String()
	request.ThreadID = id.String()
	request.Body = protocol.AuthorizationRequestMessageBody{
		CallbackURL: callbackURL,
		Reason:      reason,
		Message:     message,
		Scope:       []protocol.ZeroKnowledgeProofRequest{},
	}
	request.From = sender

	return &request, nil
}

// VerifyAuthResponse performs verification of auth response based on auth request
func (v *Verifier) VerifyAuthResponse(ctx context.Context, response protocol.AuthorizationResponseMessage, request protocol.AuthorizationRequestMessage) error {

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
		queryBytes, err := json.Marshal(proofRequest.Rules["query"])
		if err != nil {
			return err
		}
		var query pubsignals.Query
		err = json.Unmarshal(queryBytes, &query)
		if err != nil {
			return err
		}
		// verify query
		err = cv.VerifyQuery(ctx, query)
		if err != nil {
			return err
		}

		err = cv.VerifyStates(ctx, v.opts)
		if err != nil {
			return err
		}
	}

	return nil
}

// VerifyJWZ performs verification of jwz token
func (v *Verifier) VerifyJWZ(ctx context.Context, token string) (t *jwz.Token, err error) {

	t, err = jwz.Parse(token)
	if err != nil {
		return nil, err
	}

	verificationKey, err := v.verificationKeyLoader.Load(circuits.CircuitID(t.CircuitID))
	if err != nil {
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

	err = circuitVerifier.VerifyStates(ctx, v.opts)
	if err != nil {
		return nil, err
	}

	return
}

// FullVerify performs verification of jwz token and auth request
func (v *Verifier) FullVerify(ctx context.Context, token string, request protocol.AuthorizationRequestMessage) error {

	//// verify jwz
	t, err := v.VerifyJWZ(ctx, token)
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
	err = v.VerifyAuthResponse(ctx, authMsgResponse, request)
	return err
}

// VerifyState allows to verify state without binding to  verifier instance
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

	//var cv pubsignals.Verifier
	//switch circuitID {
	//case circuits.AuthCircuitID:
	//	cv = &pubsignals.Auth{}
	//case circuits.AtomicQueryMTPCircuitID:
	//	cv = &pubsignals.AtomicQueryMTP{}
	//case circuits.AtomicQuerySigCircuitID:
	//	cv = &pubsignals.AtomicQuerySig{}
	//default:
	//	return nil, errors.Errorf("circuit verifier is not defined for %s", circuitID)
	//}
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
