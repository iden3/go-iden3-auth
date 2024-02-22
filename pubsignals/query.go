package pubsignals

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"
	"time"

	"github.com/iden3/go-circuits/v2"
	core "github.com/iden3/go-iden3-core/v2"
	parser "github.com/iden3/go-schema-processor/v2/json"
	"github.com/iden3/go-schema-processor/v2/merklize"
	"github.com/iden3/go-schema-processor/v2/utils"
	"github.com/piprate/json-gold/ld"
	"github.com/pkg/errors"
)

var allOperations = map[int]struct{}{
	circuits.EQ:      {},
	circuits.LT:      {},
	circuits.LTE:     {},
	circuits.GT:      {},
	circuits.GTE:     {},
	circuits.IN:      {},
	circuits.NIN:     {},
	circuits.NE:      {},
	circuits.BETWEEN: {},
	circuits.NULLIFY: {},
}

var availableTypesOperations = map[string]map[int]struct{}{
	ld.XSDBoolean:                   {circuits.EQ: {}, circuits.NE: {}},
	ld.XSDInteger:                   allOperations,
	ld.XSDNS + "nonNegativeInteger": allOperations,
	ld.XSDNS + "positiveInteger":    allOperations,
	ld.XSDString:                    {circuits.EQ: {}, circuits.NE: {}, circuits.IN: {}, circuits.NIN: {}},
	ld.XSDNS + "dateTime":           allOperations,
	ld.XSDDouble:                    {circuits.EQ: {}, circuits.NE: {}, circuits.IN: {}, circuits.NIN: {}},
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
	ErrInvalidValues = errors.New("proof was generated for anther values")
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
	_ context.Context,
	loader ld.DocumentLoader,
	pubSig *CircuitOutputs,
	verifiablePresentation json.RawMessage,
	supportSdOperator bool,
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

	if err := q.verifyCredentialSubject(pubSig, verifiablePresentation,
		schemaBytes, loader, supportSdOperator); err != nil {
		return err
	}

	if !q.SkipClaimRevocationCheck && pubSig.IsRevocationChecked == 0 {
		return errors.New("check revocation is required")
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

	return q.verifyClaim(schemaBytes, pubSig, loader)
}

func (q Query) verifyClaim(schemaBytes []byte, pubSig *CircuitOutputs,
	schemaLoader ld.DocumentLoader) error {

	if len(q.CredentialSubject) == 0 {
		return nil
	}

	fieldName, _, err := extractQueryFields(q.CredentialSubject)
	if err != nil {
		return err
	}

	if pubSig.Merklized == 1 {
		path, err := merklize.Options{DocumentLoader: schemaLoader}.
			FieldPathFromContext(schemaBytes, q.Type, fieldName)
		if err != nil {
			return err
		}

		err = path.Prepend(PathToSubjectType)
		if err != nil {
			return err
		}

		mkPath, err := path.MtEntry()
		if err != nil {
			return err
		}

		if mkPath.Cmp(pubSig.ClaimPathKey) != 0 {
			return errors.New("proof was generated for another path")
		}
		if pubSig.ClaimPathNotExists == 1 {
			return errors.New("proof doesn't contains target query key")
		}
	} else {
		slotIndex, err := parser.Parser{}.GetFieldSlotIndex(fieldName, q.Type, schemaBytes)
		if err != nil {
			return errors.Errorf("failed to get field slot: %v", err)
		}
		if slotIndex != pubSig.SlotIndex {
			return errors.New("proof was generated for another slot")
		}
	}

	return nil
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

func (q Query) verifyCredentialSubject(
	pubSig *CircuitOutputs,
	verifiablePresentation json.RawMessage,
	ctxBytes []byte,
	schemaLoader ld.DocumentLoader,
	supportSdOperator bool,
) error {

	ctx := context.Background()

	queriesMetadata, err := ParseQueriesMetadata(ctx, q.Type, string(ctxBytes), q.CredentialSubject, merklize.Options{DocumentLoader: schemaLoader})
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

	// validate selectivity disclosure request
	if metadata.Operator == circuits.SD {
		return q.validateDisclosure(ctx, pubSig, metadata.FieldName,
			verifiablePresentation, schemaLoader, supportSdOperator)
	}

	// validate empty credential subject request
	if q.isEmptyCredentialSubject(metadata.Operator, pubSig.Merklized) {
		return q.verifyEmptyCredentialSubject(pubSig)
	}

	if metadata.Operator != pubSig.Operator {
		return ErrRequestOperator
	}

	if metadata.Operator == circuits.NOOP {
		return nil
	}

	if len(metadata.Values) > len(pubSig.Value) {
		return ErrValuesSize
	}

	if len(metadata.Values) < pubSig.ValueArraySize {
		diff := pubSig.ValueArraySize - len(metadata.Values)
		for diff > 0 {
			metadata.Values = append(metadata.Values, big.NewInt(0))
			diff--
		}
	}

	for i := 0; i < len(metadata.Values); i++ {
		if metadata.Values[i].Cmp(pubSig.Value[i]) != 0 {
			return ErrInvalidValues
		}
	}

	return nil
}

func (q Query) validateDisclosure(ctx context.Context, pubSig *CircuitOutputs,
	key string, verifiablePresentation json.RawMessage,
	schemaLoader ld.DocumentLoader, suppordSdOperator bool) error {

	if verifiablePresentation == nil {
		return errors.New("selective disclosure value is missed")
	}

	mz, err := merklize.MerklizeJSONLD(ctx,
		bytes.NewBuffer(verifiablePresentation),
		merklize.WithDocumentLoader(schemaLoader))
	if err != nil {
		return errors.Errorf("failed to merklize doc: %v", err)
	}

	merklizedPath, err := merklize.Options{DocumentLoader: schemaLoader}.
		NewPathFromDocument(verifiablePresentation,
			fmt.Sprintf("verifiableCredential.credentialSubject.%s", key))
	if err != nil {
		return errors.Errorf("failed build path to '%s' key: %v", key, err)
	}

	proof, valueByPath, err := mz.Proof(ctx, merklizedPath)
	if err != nil {
		return errors.Errorf("failed get raw value: %v", err)
	}
	if !proof.Existence {
		return errors.Errorf("path '%v' doesn't exist in document", merklizedPath.Parts())
	}

	mvBig, err := valueByPath.MtEntry()
	if err != nil {
		return errors.Errorf("failed to hash value: %v", err)
	}

	if !suppordSdOperator {
		if pubSig.Operator != circuits.EQ {
			return errors.New("selective disclosure available only for equal operation")
		}

		for i := 1; i < len(pubSig.Value); i++ {
			if pubSig.Value[i].Cmp(big.NewInt(0)) != 0 {
				return errors.New("selective disclosure not available for array of values")
			}
		}

		if pubSig.Value[0].Cmp(mvBig) != 0 {
			return errors.New("different value between proof and disclosure value")
		}

	} else {
		if pubSig.Operator != circuits.SD {
			return errors.New("invalid pub signal operator for selective disclosure")
		}

		if pubSig.OperatorOutput == nil || pubSig.OperatorOutput.Cmp(mvBig) != 0 {
			return errors.New("operator output should be equal to disclosed value")
		}
		for i := 0; i < len(pubSig.Value); i++ {
			if pubSig.Value[i].Cmp(big.NewInt(0)) != 0 {
				return errors.New("selective disclosure values should be zero")
			}
		}

	}

	return nil
}

func (q Query) verifyEmptyCredentialSubject(
	pubSig *CircuitOutputs,
) error {
	if pubSig.Operator != circuits.EQ {
		return errors.New("empty credentialSubject request available only for equal operation")
	}

	for i := 1; i < len(pubSig.Value); i++ {
		if pubSig.Value[i].Cmp(big.NewInt(0)) != 0 {
			return errors.New("empty credentialSubject request not available for array of values")
		}
	}

	p, err := merklize.NewPath("https://www.w3.org/2018/credentials#credentialSubject")
	if err != nil {
		return err
	}
	bi, err := p.MtEntry()
	if err != nil {
		return err
	}

	if pubSig.ClaimPathKey.Cmp(bi) != 0 {
		return errors.New("proof doesn't contain credentialSubject in claimPathKey")
	}

	return nil
}

func (q Query) isEmptyCredentialSubject(
	operator,
	isMerklized int,
) bool {
	return q.CredentialSubject == nil && operator == circuits.NOOP && isMerklized == 1
}

func extractQueryFields(req map[string]interface{}) (fieldName string, fieldPredicate map[string]interface{}, err error) {

	if len(req) > 1 {
		return "", nil, errors.New("multiple requests not supported")
	}

	for field, body := range req {
		fieldName = field
		var ok bool
		fieldPredicate, ok = body.(map[string]interface{})
		if !ok {
			return "", nil, errors.New("failed cast type map[string]interface")
		}
		if len(fieldPredicate) > 1 {
			return "", nil, errors.New("multiple predicates for one field not supported")
		}
		break
	}
	return fieldName, fieldPredicate, nil
}

func isPositiveInteger(v interface{}) bool {
	number, err := strconv.ParseFloat(fmt.Sprintf("%v", v), 64)
	if err != nil {
		// value is not a number
		return true
	}
	return number >= 0
}

// IsValidOperation checks if operation and type are supported.
func IsValidOperation(typ string, op int) bool {
	if op == circuits.NOOP {
		return true
	}

	ops, ok := availableTypesOperations[typ]
	if !ok {
		// by default all unknown types will be considered as string
		ops = availableTypesOperations[ld.XSDString]
		_, ok = ops[op]
		return ok
	}

	_, ok = ops[op]
	return ok
}
