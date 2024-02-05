package auth

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
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
	"github.com/iden3/go-iden3-core/v2/w3c"
	"github.com/iden3/go-jwz/v2"
	schemaloaders "github.com/iden3/go-schema-processor/v2/loaders"
	"github.com/iden3/go-schema-processor/v2/merklize"
	"github.com/iden3/go-schema-processor/v2/verifiable"
	"github.com/iden3/iden3comm/v2"
	"github.com/iden3/iden3comm/v2/packers"
	"github.com/iden3/iden3comm/v2/protocol"
	shell "github.com/ipfs/go-ipfs-api"
	"github.com/piprate/json-gold/ld"
	"github.com/pkg/errors"
)

var defaultSchemaLoader ld.DocumentLoader

// SetDocumentLoader sets the default schema loader that would be used if
// other is not set with WithDocumentLoader option. Also, this document loader
// is set for go-schema-processor library to use it for merklize.
func SetDocumentLoader(schemaLoader ld.DocumentLoader) {
	defaultSchemaLoader = schemaLoader
	merklize.SetDocumentLoader(schemaLoader)
}

// UniversalResolverURL is a url for universal resolver
const UniversalResolverURL = "https://dev.uniresolver.io/1.0/identifiers"

// UniversalDIDResolver is a resolver for universal resolver
var UniversalDIDResolver = packers.DIDResolverHandlerFunc(func(did string) (*verifiable.DIDDocument, error) {
	didDoc := &verifiable.DIDDocument{}

	resp, err := http.Get(fmt.Sprintf("%s/%s", UniversalResolverURL, did))

	if err != nil {
		return nil, err
	}

	defer func() {
		err := resp.Body.Close()
		if err != nil {
			log.Fatal(err)
		}
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var didMetadata map[string]interface{}

	err = json.Unmarshal(body, &didMetadata)
	if err != nil {
		return nil, err
	}

	doc, ok := didMetadata["didDocument"]

	if !ok {
		return nil, errors.New("did document not found")
	}

	docBts, err := json.Marshal(doc)

	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(docBts, &didDoc)

	if err != nil {
		return nil, err
	}

	return didDoc, nil
})

// Verifier is a struct for auth instance
type Verifier struct {
	verificationKeyLoader loaders.VerificationKeyLoader
	documentLoader        ld.DocumentLoader
	stateResolver         map[string]pubsignals.StateResolver
	packageManager        iden3comm.PackageManager
}

// VerifierOption is a function to set options for Verifier instance
type VerifierOption func(opts *verifierOpts)

// WithDocumentLoader sets the document loader for Verifier instance
func WithDocumentLoader(docLoader ld.DocumentLoader) VerifierOption {
	return func(opts *verifierOpts) {
		opts.docLoader = docLoader
	}
}

// WithIPFSClient sets the IPFS client for document loader of Verifier instance.
// If document loader is set with WithDocumentLoader function, this option is
// ignored.
func WithIPFSClient(ipfsCli *shell.Shell) VerifierOption {
	return func(opts *verifierOpts) {
		opts.ipfsCli = ipfsCli
	}
}

// WithIPFSGateway sets the IPFS gateway for document loader of Verifier
// instance. If document loader is set with WithDocumentLoader function, this
// option is ignored. If WithIPFSClient is set, this option is ignored also.
func WithIPFSGateway(ipfsGW string) VerifierOption {
	return func(opts *verifierOpts) {
		opts.ipfsGW = ipfsGW
	}
}

// WithDIDResolver sets the DID resolver for Verifier instance. The default
// value is UniversalDIDResolver.
func WithDIDResolver(resolver packers.DIDResolverHandlerFunc) VerifierOption {
	return func(opts *verifierOpts) {
		opts.didResolver = resolver
	}
}

type verifierOpts struct {
	docLoader   ld.DocumentLoader
	ipfsCli     *shell.Shell
	ipfsGW      string
	didResolver packers.DIDResolverHandlerFunc
}

func newOpts() verifierOpts {
	return verifierOpts{
		didResolver: UniversalDIDResolver,
	}
}

// NewVerifier returns setup instance of auth library
func NewVerifier(
	keyLoader loaders.VerificationKeyLoader,
	resolver map[string]pubsignals.StateResolver,
	opts ...VerifierOption,
) (*Verifier, error) {
	vOpts := newOpts()
	for _, optFn := range opts {
		optFn(&vOpts)
	}

	docLoader := getDocumentLoader(vOpts.docLoader, vOpts.ipfsCli,
		vOpts.ipfsGW)
	v := &Verifier{
		verificationKeyLoader: keyLoader,
		documentLoader:        docLoader,
		stateResolver:         resolver,
		packageManager:        *iden3comm.NewPackageManager(),
	}

	err := v.SetupAuthV2ZKPPacker()
	if err != nil {
		return nil, err
	}

	err = v.SetupJWSPacker(vOpts.didResolver)
	if err != nil {
		return nil, err
	}

	return v, nil
}

// SetPackageManager sets the package manager for the VerifierBuilder.
func (v *Verifier) SetPackageManager(manager iden3comm.PackageManager) {
	v.packageManager = manager
}

// SetPacker sets the custom packer manager for the VerifierBuilder.
func (v *Verifier) SetPacker(packer iden3comm.Packer) error {
	return v.packageManager.RegisterPackers(packer)
}

// SetupAuthV2ZKPPacker sets the custom packer manager for the VerifierBuilder.
func (v *Verifier) SetupAuthV2ZKPPacker() error {
	authV2Set, err := v.verificationKeyLoader.Load(circuits.AuthV2CircuitID)
	if err != nil {
		return fmt.Errorf("failed upload circuits files: %w", err)
	}

	provers := make(map[jwz.ProvingMethodAlg]packers.ProvingParams)

	verifications := make(map[jwz.ProvingMethodAlg]packers.VerificationParams)

	verifications[jwz.AuthV2Groth16Alg] = packers.NewVerificationParams(
		authV2Set,
		func(id circuits.CircuitID, pubSignals []string) error {
			if id != circuits.AuthV2CircuitID {
				return errors.New("circuit id is not AuthV2CircuitID")
			}
			verifier, err := pubsignals.GetVerifier(circuits.AuthV2CircuitID)
			if err != nil {
				return err
			}
			pubSignalBytes, err := json.Marshal(pubSignals)
			if err != nil {
				return err
			}
			err = verifier.PubSignalsUnmarshal(pubSignalBytes)
			if err != nil {
				return err
			}
			return verifier.VerifyStates(context.Background(), v.stateResolver)
		},
	)

	zkpPackerV2 := packers.NewZKPPacker(
		provers,
		verifications,
	)
	return v.packageManager.RegisterPackers(zkpPackerV2)
}

// SetupJWSPacker sets the JWS packer for the VerifierBuilder.
func (v *Verifier) SetupJWSPacker(didResolver packers.DIDResolverHandlerFunc) error {

	signerFnStub := packers.SignerResolverHandlerFunc(func(kid string) (crypto.Signer, error) {
		return nil, nil
	})
	jwsPacker := packers.NewJWSPacker(didResolver, signerFnStub)

	return v.packageManager.RegisterPackers(jwsPacker)
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

// CreateContractInvokeRequest creates new contract invoke request message
// reason - describes purpose of request
// sender - sender identifier
// transactionData - data for on chain verification
// zkRequests - zero knowledge proof request(s)
func CreateContractInvokeRequest(
	reason, sender string,
	transactionData protocol.TransactionData,
	zkRequests ...protocol.ZeroKnowledgeProofRequest,
) protocol.ContractInvokeRequestMessage {
	return CreateContractInvokeRequestWithMessage(reason, "", sender, transactionData, zkRequests...)
}

// CreateContractInvokeRequestWithMessage creates new contract invoke request message with message
func CreateContractInvokeRequestWithMessage(
	reason, message, sender string,
	transactionData protocol.TransactionData,
	zkRequests ...protocol.ZeroKnowledgeProofRequest,
) protocol.ContractInvokeRequestMessage {
	reqID := uuid.New().String()
	return protocol.ContractInvokeRequestMessage{
		Typ:      packers.MediaTypePlainMessage,
		Type:     protocol.ContractInvokeRequestMessageType,
		ID:       reqID,
		ThreadID: reqID,
		From:     sender,
		Body: protocol.ContractInvokeRequestMessageBody{
			Reason:          reason,
			Message:         message,
			TransactionData: transactionData,
			Scope:           zkRequests,
		},
	}
}

// VerifyAuthRequest verifies auth request message
func VerifyAuthRequest(request protocol.AuthorizationRequestMessage) error {
	groupIDValidationMap := make(map[int][]pubsignals.Query)

	for _, proofRequest := range request.Body.Scope {
		proofRequestQuery, err := unmarshalQuery(proofRequest.Query)
		if err != nil {
			return err
		}
		groupID := proofRequestQuery.GroupID
		if groupID != 0 {
			existingQueries := groupIDValidationMap[groupID]

			// Validate that all requests in the group have the same schema, issuer, and circuit
			for _, existingQuery := range existingQueries {
				if existingQuery.Type != proofRequestQuery.Type {
					return errors.New("all requests in the group should have the same type")
				}

				if existingQuery.Context != proofRequestQuery.Context {
					return errors.New("all requests in the group should have the same context")
				}

				allowedIssuers := proofRequestQuery.AllowedIssuers
				existingRequestAllowedIssuers := existingQuery.AllowedIssuers
				if !checkIssuersEquality(allowedIssuers, existingRequestAllowedIssuers) {
					return errors.New("all requests in the group should have the same issuer")
				}
			}

			groupIDValidationMap[groupID] = append(existingQueries, proofRequestQuery)
		}
	}

	return nil
}

func unmarshalQuery(queryMap map[string]interface{}) (out pubsignals.Query, err error) {
	// prepare query from request
	queryBytes, err := json.Marshal(queryMap)
	if err != nil {
		return out, err
	}
	err = json.Unmarshal(queryBytes, &out)
	if err != nil {
		return out, err
	}
	return out, nil
}

func checkIssuersEquality(issuers1, issuers2 []string) bool {
	if len(issuers1) != len(issuers2) {
		return false
	}

	for _, issuer := range issuers1 {
		found := false
		for _, existingIssuer := range issuers2 {
			if issuer == existingIssuer || existingIssuer == "*" {
				found = true
				break
			}
		}

		if !found {
			return false
		}
	}

	return true
}

type linkIdRequestId struct {
	linkID    *big.Int
	requestID uint32
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

	if request.From != response.To {
		return errors.Errorf("sender of the request is not a target of response - expected %s, given %s", request.From, response.To)
	}

	err := VerifyAuthRequest(request)
	if err != nil {
		return err
	}

	groupIDToLinkIDMap := make(map[int][]linkIdRequestId)
	for _, proofRequest := range request.Body.Scope {
		// prepare query from request
		query, err := unmarshalQuery(proofRequest.Query)
		if err != nil {
			return err
		}
		groupID := query.GroupID

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

		if proofRequest.Params == nil {
			proofRequest.Params = make(map[string]interface{})
		}
		verifierDID, err := w3c.ParseDID(request.From) // TODO: this is assuming that response.TO is always DID.
		if err != nil {
			return err
		}
		proofRequest.Params[pubsignals.ParamNameVerifierDID] = verifierDID

		pubSignals, err := cv.VerifyQuery(ctx, query, v.documentLoader, rawMessage, proofRequest.Params, opts...)
		if err != nil {
			return err
		}

		err = cv.VerifyStates(ctx, v.stateResolver, opts...)
		if err != nil {
			return err
		}

		if response.From == "" {
			return errors.Errorf("proof response doesn't contain from field")
		}

		err = verifyGroupIdMathch(pubSignals.LinkID, groupID, proofResponse.ID, groupIDToLinkIDMap)
		if err != nil {
			return err
		}

	}

	return nil
}

func verifyGroupIdMathch(linkID *big.Int, groupID int, requestID uint32, groupIDToLinkIDMap map[int][]linkIdRequestId) error {
	if groupID == 0 {
		return nil
	}
	if linkID != nil {
		if existingLinks, exists := groupIDToLinkIDMap[groupID]; exists {
			linkIDMap := linkIdRequestId{linkID: linkID, requestID: requestID}
			groupIDToLinkIDMap[groupID] = append(existingLinks, linkIDMap)
		} else {
			linkIDMap := linkIdRequestId{linkID: linkID, requestID: requestID}
			groupIDToLinkIDMap[groupID] = []linkIdRequestId{linkIDMap}
		}
	}
	// verify grouping links
	for groupIDfromMap, metas := range groupIDToLinkIDMap {
		// Check that all linkIDs are the same
		if len(metas) > 1 {
			firstLinkID := metas[0].linkID
			for _, meta := range metas[1:] {
				if meta.linkID.Cmp(firstLinkID) != 0 {
					return errors.Errorf("Link id validation failed for group %d, request linkID to requestIds info: %v", groupIDfromMap, metas)
				}
			}
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

	msg, _, err := v.packageManager.Unpack([]byte(token))
	if err != nil {
		return nil, err
	}
	msgBytes, err := json.Marshal(msg)
	if err != nil {
		return nil, err
	}

	var authMsgResponse protocol.AuthorizationResponseMessage
	err = json.Unmarshal(msgBytes, &authMsgResponse)

	if err != nil {
		return nil, err
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

func getDocumentLoader(docLoader ld.DocumentLoader, ipfsCli *shell.Shell,
	ipfsGW string) ld.DocumentLoader {

	if docLoader != nil {
		return docLoader
	}

	if ipfsCli == nil && ipfsGW == "" && defaultSchemaLoader != nil {
		return defaultSchemaLoader
	}

	return schemaloaders.NewDocumentLoader(ipfsCli, ipfsGW)
}
