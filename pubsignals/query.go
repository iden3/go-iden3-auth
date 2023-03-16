package pubsignals

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/iden3/go-circuits"
	"github.com/iden3/go-iden3-auth/loaders"
	core "github.com/iden3/go-iden3-core"
	jsonSuite "github.com/iden3/go-schema-processor/json"
	"github.com/iden3/go-schema-processor/merklize"
	"github.com/iden3/go-schema-processor/utils"
	"github.com/piprate/json-gold/ld"
	"github.com/pkg/errors"
)

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
)

// Query represents structure for query to atomic circuit.
type Query struct {
	AllowedIssuers           []string               `json:"allowedIssuers"`
	CredentialSubject        map[string]interface{} `json:"credentialSubject,omitempty"`
	Context                  string                 `json:"context"`
	Type                     string                 `json:"type"`
	ClaimID                  string                 `json:"claimId,omitempty"`
	SkipClaimRevocationCheck bool                   `json:"skipClaimRevocationCheck,omitempty"`
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
}

// Check checks if proof was created for this query.
func (q Query) Check(
	ctx context.Context,
	loader loaders.SchemaLoader,
	pubSig *CircuitOutputs,
	verifiablePresentation json.RawMessage,
) error {
	if err := q.verifyIssuer(pubSig); err != nil {
		return err
	}

	if err := q.verifySchemaID(pubSig); err != nil {
		return err
	}

	schemaBytes, _, err := loader.Load(ctx, q.Context)
	if err != nil {
		return fmt.Errorf("failed load schema by context: %w", err)
	}

	if err := q.verifyCredentialSubject(
		pubSig,
		verifiablePresentation,
		schemaBytes,
	); err != nil {
		return err
	}

	if !q.SkipClaimRevocationCheck && pubSig.IsRevocationChecked == 0 {
		return errors.New("check revocation is required")
	}

	return q.verifyClaim(ctx, schemaBytes, pubSig)
}

func (q Query) verifyClaim(_ context.Context, schemaBytes []byte, pubSig *CircuitOutputs) error {
	if len(q.CredentialSubject) == 0 {
		return nil
	}

	fieldName, _, err := extractQueryFields(q.CredentialSubject)
	if err != nil {
		return err
	}

	if pubSig.Merklized == 1 {
		path, err := merklize.NewFieldPathFromContext(schemaBytes, q.Type, fieldName)
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
		slotIdx, err := jsonSuite.Parser{}.GetFieldSlotIndex(fieldName, schemaBytes)
		if err != nil {
			return err
		}
		if pubSig.SlotIndex != slotIdx {
			return errors.New("different slot index for claim")
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

func (q Query) verifySchemaID(pubSig *CircuitOutputs) error {
	schemaID := fmt.Sprintf("%s#%s", q.Context, q.Type)
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
) error {
	fieldName, predicate, err := extractQueryFields(q.CredentialSubject)
	if err != nil {
		return err
	}

	var fieldType string
	if fieldName != "" {
		fieldType, err = merklize.TypeFromContext(
			ctxBytes,
			fmt.Sprintf("%s.%s", q.Type, fieldName),
		)
		if err != nil {
			return err
		}
	}

	if q.CredentialSubject != nil && len(predicate) == 0 {
		ctx := context.Background()
		if err := q.validateDisclosure(
			ctx,
			pubSig,
			fieldName,
			fieldType,
			verifiablePresentation,
		); err != nil {
			return err
		}
		return nil
	}

	if fieldType != "" && !isTypeSupportedForNonSC(fieldType) {
		return errors.Errorf("%s type is supported only for disclosure request", fieldType)
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

func (q Query) validateDisclosure(
	ctx context.Context,
	pubSig *CircuitOutputs,
	key string,
	fieldType string,
	verifiablePresentation json.RawMessage,
) error {
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

	mz, err := merklize.MerklizeJSONLD(ctx, bytes.NewBuffer(verifiablePresentation))
	if err != nil {
		return errors.Errorf("failed to merklize doc: %v", err)
	}

	merklizedPath, err := merklize.NewPathFromDocument(verifiablePresentation, fmt.Sprintf("verifiableCredential.%s", key))
	if err != nil {
		return errors.Errorf("failed build path to '%s' key: %v", key, err)
	}

	valueByPath, err := mz.RawValue(merklizedPath)
	if err != nil {
		return errors.Errorf("failed get raw value: %v", err)
	}

	mvBig, err := merklize.HashValue(fieldType, valueByPath)
	if err != nil {
		return errors.Errorf("failed to hash value: %v", err)
	}

	if pubSig.Value[0].Cmp(mvBig) != 0 {
		return errors.New("different value between proof and disclosure value")
	}

	return nil
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
			hashedValue, err := merklize.HashValue(valueType, item)
			if err != nil {
				return nil, err
			}
			values[i] = hashedValue
		}
		return values, nil
	}

	hashedValue, err := merklize.HashValue(valueType, v)
	if err != nil {
		return nil, err
	}
	values = append(values, hashedValue)

	return values, nil
}

// by default all types except boolean, integer, dateTime will consider as string types
// but string type is possible only for selective disclosure request
func isTypeSupportedForNonSC(t string) bool {
	switch t {
	case ld.XSDBoolean:
		return true
	case ld.XSDInteger,
		ld.XSDNS + "nonNegativeInteger",
		ld.XSDNS + "nonPositiveInteger",
		ld.XSDNS + "negativeInteger",
		ld.XSDNS + "positiveInteger":
		return true
	case ld.XSDNS + "dateTime":
		return true
	}
	return false
}
