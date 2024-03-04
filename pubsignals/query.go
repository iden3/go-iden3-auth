package pubsignals

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"time"

	"github.com/iden3/go-circuits/v2"
	core "github.com/iden3/go-iden3-core/v2"
	"github.com/iden3/go-schema-processor/v2/merklize"
	"github.com/iden3/go-schema-processor/v2/utils"
	"github.com/piprate/json-gold/ld"
	"github.com/pkg/errors"
)

var allOperations = map[int]struct{}{
	circuits.EQ:         {},
	circuits.LT:         {},
	circuits.LTE:        {},
	circuits.GT:         {},
	circuits.GTE:        {},
	circuits.IN:         {},
	circuits.NIN:        {},
	circuits.NE:         {},
	circuits.BETWEEN:    {},
	circuits.NULLIFY:    {},
	circuits.EXISTS:     {},
	circuits.NONBETWEEN: {},
}

var availableTypesOperations = map[string]map[int]struct{}{
	ld.XSDBoolean:                   {circuits.EQ: {}, circuits.NE: {}, circuits.EXISTS: {}},
	ld.XSDInteger:                   allOperations,
	ld.XSDNS + "nonNegativeInteger": allOperations,
	ld.XSDNS + "positiveInteger":    allOperations,
	ld.XSDString:                    {circuits.EQ: {}, circuits.NE: {}, circuits.IN: {}, circuits.NIN: {}, circuits.EXISTS: {}},
	ld.XSDNS + "dateTime":           allOperations,
	ld.XSDDouble:                    {circuits.EQ: {}, circuits.NE: {}, circuits.IN: {}, circuits.NIN: {}, circuits.EXISTS: {}},
}

// PathToSubjectType path to description of subject type.
const PathToSubjectType = "https://www.w3.org/2018/credentials#credentialSubject"

var (
	// ErrUnavailableIssuer issuer from proof not allowed.
	ErrUnavailableIssuer = errors.New("issuer not exists in query access list")
	// ErrSchemaID proof was created for different schema.
	ErrSchemaID = errors.New("proof was generated for another schema")
	// ErrRequestOperator proof was created for different query.
	ErrRequestOperator = errors.New("proof was generated for another query operator")
	// ErrValuesSize proof was created for different values.
	ErrValuesSize = errors.New("query asked proof about more values")
	// ErrInvalidValues proof was created for different values.
	ErrInvalidValues = errors.New("proof was generated for another values")
	// ErrNegativeValue only positive integers allowed.
	ErrNegativeValue = errors.New("negative values not supported")
)

// Query represents structure for query to atomic circuit.
type Query struct {
	AllowedIssuers           []string               `json:"allowedIssuers"`
	CredentialSubject        map[string]interface{} `json:"credentialSubject,omitempty"`
	Context                  string                 `json:"context"`
	Type                     string                 `json:"type"`
	ClaimID                  string                 `json:"claimId,omitempty"`
	SkipClaimRevocationCheck bool                   `json:"skipClaimRevocationCheck,omitempty"`
	ProofType                string                 `json:"proofType"`
	GroupID                  int                    `json:"groupId"`
}

// CircuitVerificationResult struct for verification result.
type CircuitVerificationResult struct {
	LinkID *big.Int
}

// CircuitOutputs pub signals from circuit.
type CircuitOutputs struct {
	IssuerID            *core.ID
	ClaimSchema         core.SchemaHash
	SlotIndex           int
	Operator            int
	Value               []*big.Int
	Timestamp           int64
	Merklized           int
	ClaimPathKey        *big.Int
	ClaimPathNotExists  int
	ValueArraySize      int
	IsRevocationChecked int
	// V3 NEW
	LinkID             *big.Int
	VerifierID         *core.ID
	NullifierSessionID *big.Int

	OperatorOutput *big.Int
	Nullifier      *big.Int
	ProofType      int
}

// Check checks if proof was created for this query.
// Would be good to use ctx for external http requests, but current interfaces
// doesn't allow to do it. Left it for future.
func (q Query) Check(
	ctx context.Context,
	loader ld.DocumentLoader,
	pubSig *CircuitOutputs,
	verifiablePresentation json.RawMessage,
	circuitID circuits.CircuitID,
	opts ...VerifyOpt,
) error {
	if err := q.verifyIssuer(pubSig); err != nil {
		return err
	}

	schemaDoc, err := loader.LoadDocument(q.Context)
	if err != nil {
		return fmt.Errorf("failed load schema by context: %w", err)
	}

	schemaBytes, err := json.Marshal(schemaDoc.Document)
	if err != nil {
		return fmt.Errorf("failed jsonify schema document: %w", err)
	}

	if err := q.verifySchemaID(schemaBytes, pubSig, loader); err != nil {
		return err
	}
	if !q.SkipClaimRevocationCheck && pubSig.IsRevocationChecked == 0 {
		return errors.New("check revocation is required")
	}

	queriesMetadata, err := ParseQueriesMetadata(ctx, q.Type, string(schemaBytes), q.CredentialSubject, merklize.Options{DocumentLoader: loader})
	if err != nil {
		return err
	}

	if len(queriesMetadata) > 1 {
		return errors.New("multiple requests not supported")
	}

	var metadata QueryMetadata
	if len(queriesMetadata) == 1 {
		metadata = queriesMetadata[0]
	}

	cfg := defaultProofVerifyOpts
	for _, o := range opts {
		o(&cfg)
	}

	if time.Since(
		time.Unix(pubSig.Timestamp, 0),
	) > cfg.AcceptedProofGenerationDelay {
		return ErrProofGenerationOutdated
	}

	switch circuitID {
	case circuits.AtomicQueryV3CircuitID:
		err = verifyCredentialSubjectV3(pubSig, verifiablePresentation, loader, metadata)
		if err != nil {
			return err
		}
		return q.verifyFieldValueInclusionV2(pubSig, metadata)
	case circuits.AtomicQueryMTPV2CircuitID, circuits.AtomicQuerySigV2CircuitID:
		err = verifyCredentialSubjectV2(pubSig, verifiablePresentation, loader, metadata)
		if err != nil {
			return err
		}
		return q.verifyFieldValueInclusionV3(pubSig, metadata)

	default:
		return errors.Errorf("circuit id %s is not supported", circuitID)
	}

}

func (q Query) verifyIssuer(pubSig *CircuitOutputs) error {
	userDID, err := core.ParseDIDFromID(*pubSig.IssuerID)
	if err != nil {
		return err
	}
	for _, issuer := range q.AllowedIssuers {
		if issuer == "*" || issuer == userDID.String() {
			return nil
		}
	}
	return ErrUnavailableIssuer
}

func (q Query) verifySchemaID(schemaBytes []byte, pubSig *CircuitOutputs,
	schemaLoader ld.DocumentLoader) error {

	schemaID, err := merklize.Options{DocumentLoader: schemaLoader}.
		TypeIDFromContext(schemaBytes, q.Type)
	if err != nil {
		return err
	}
	querySchema := utils.CreateSchemaHash([]byte(schemaID))
	if querySchema.BigInt().Cmp(pubSig.ClaimSchema.BigInt()) == 0 {
		return nil
	}
	return ErrSchemaID
}
