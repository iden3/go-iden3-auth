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
	verifiable "github.com/iden3/go-schema-processor/v2/verifiable"
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
	ld.XSDBoolean:                        {circuits.EQ: {}, circuits.NE: {}},
	ld.XSDInteger:                        allOperations,
	ld.XSDInteger + "nonNegativeInteger": allOperations,
	ld.XSDInteger + "positiveInteger":    allOperations,
	ld.XSDString:                         {circuits.EQ: {}, circuits.NE: {}, circuits.IN: {}, circuits.NIN: {}},
	ld.XSDNS + "dateTime":                allOperations,
	ld.XSDDouble:                         {circuits.EQ: {}, circuits.NE: {}, circuits.IN: {}, circuits.NIN: {}},
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
	LinkNonce                string                 `json:"linkNonce,omitempty"`
	ProofType                string                 `json:"proofType"`
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
	LinkID         *big.Int
	VerifierID     *core.ID
	OperatorOutput *big.Int
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
		schemaBytes, loader); err != nil {
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

	// V3 NEW
	switch q.ProofType {
	case string(verifiable.BJJSignatureProofType):
		if pubSig.ProofType != 1 {
			return ErrWronProofType
		}
	case string(verifiable.Iden3SparseMerkleTreeProofType):
		if pubSig.ProofType != 2 {
			return ErrWronProofType
		}
	default:
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
) error {
	fieldName, predicate, err := extractQueryFields(q.CredentialSubject)
	if err != nil {
		return err
	}

	var fieldType string
	if fieldName != "" {
		fieldType, err = merklize.Options{DocumentLoader: schemaLoader}.
			TypeFromContext(ctxBytes, fmt.Sprintf("%s.%s", q.Type, fieldName))
		if err != nil {
			return err
		}
	}

	// validate selectivity disclosure request
	if q.isSelectivityDisclosure(predicate) {
		ctx := context.Background()
		return q.validateDisclosure(ctx, pubSig, fieldName,
			verifiablePresentation, schemaLoader)
	}

	// validate empty credential subject request
	if q.isEmptyCredentialSubject(predicate, pubSig.Merklized) {
		return q.verifyEmptyCredentialSubject(pubSig)
	}

	values, operator, err := parseFieldPredicate(fieldType, predicate)
	if err != nil {
		return err
	}

	if operator != pubSig.Operator {
		return ErrRequestOperator
	}

	if operator == circuits.NOOP {
		return nil
	}

	if len(values) > len(pubSig.Value) {
		return ErrValuesSize
	}

	if len(values) < pubSig.ValueArraySize {
		diff := pubSig.ValueArraySize - len(values)
		for diff > 0 {
			values = append(values, big.NewInt(0))
			diff--
		}
	}

	for i := 0; i < len(values); i++ {
		if values[i].Cmp(pubSig.Value[i]) != 0 {
			return ErrInvalidValues
		}
	}

	return nil
}

func (q Query) validateDisclosure(ctx context.Context, pubSig *CircuitOutputs,
	key string, verifiablePresentation json.RawMessage,
	schemaLoader ld.DocumentLoader) error {

	if verifiablePresentation == nil {
		return errors.New("selective disclosure value is missed")
	}

	if pubSig.Operator != circuits.EQ {
		return errors.New("selective disclosure available only for equal operation")
	}

	for i := 1; i < len(pubSig.Value); i++ {
		if pubSig.Value[i].Cmp(big.NewInt(0)) != 0 {
			return errors.New("selective disclosure not available for array of values")
		}
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

	if pubSig.Value[0].Cmp(mvBig) != 0 {
		return errors.New("different value between proof and disclosure value")
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

// func verifyLinkID(linkNonce string, claim *core.Claim, linkId string) error {
// 	linkIdCalc, err := CalculateLinkID(linkNonce, claim)
// 	if err != nil {
// 		return errors.Errorf("failed to calculate link ID: %v", err)
// 	}

// 	if linkId != linkIdCalc {
// 		return errors.Errorf("invalid link ID")
// 	}

// 	return nil
// }

// func verifyNullify(genesisID, claimSubjectProfileNonce, claimSchema, fieldValue, verifierID, crs, operatorOutput *big.Int) error {
// 	nullify, err := CalculateNullify(genesisID, claimSubjectProfileNonce, claimSchema, fieldValue, verifierID, crs)
// 	if err != nil {
// 		return errors.Errorf("failed to calculate nullify: %v", err)
// 	}

// 	if nullify != operatorOutput.String() {
// 		return errors.Errorf("invalid nullify value")
// 	}

// 	return nil
// }

func (q Query) isSelectivityDisclosure(
	predicate map[string]interface{}) bool {
	return q.CredentialSubject != nil && len(predicate) == 0
}

func (q Query) isEmptyCredentialSubject(
	predicate map[string]interface{},
	isMerklized int,
) bool {
	return q.CredentialSubject == nil && len(predicate) == 0 && isMerklized == 1
}

func parseFieldPredicate(
	fieldType string,
	fieldPredicate map[string]interface{},
) (
	values []*big.Int,
	operator int,
	err error,
) {
	for op, v := range fieldPredicate {
		var ok bool
		operator, ok = circuits.QueryOperators[op]
		if !ok {
			return nil, 0, errors.New("query operator is not supported")
		}

		if !isValidOperation(fieldType, operator) {
			return nil, 0, errors.Errorf("invalid operation '%s' for field type '%s'", op, fieldType)
		}

		values, err = getValuesAsArray(v, fieldType)
		if err != nil {
			return nil, 0, err
		}

		// only one predicate for field is supported
		break
	}
	return values, operator, nil
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

func getValuesAsArray(v interface{}, valueType string) ([]*big.Int, error) {
	var values []*big.Int

	listOfValues, ok := v.([]interface{})
	if ok {
		values = make([]*big.Int, len(listOfValues))
		for i, item := range listOfValues {
			if !isPositiveInteger(item) {
				return nil, ErrNegativeValue
			}
			hashedValue, err := merklize.HashValue(valueType, item)
			if err != nil {
				return nil, err
			}
			values[i] = hashedValue
		}
		return values, nil
	}

	if !isPositiveInteger(v) {
		return nil, ErrNegativeValue
	}
	hashedValue, err := merklize.HashValue(valueType, v)
	if err != nil {
		return nil, err
	}
	values = append(values, hashedValue)

	return values, nil
}

func isPositiveInteger(v interface{}) bool {
	number, err := strconv.ParseFloat(fmt.Sprintf("%v", v), 64)
	if err != nil {
		// value is not a number
		return true
	}
	return number >= 0
}

func isValidOperation(typ string, op int) bool {
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
