package pubsignals

import (
	"context"
	"fmt"
	"math/big"

	"github.com/iden3/go-circuits"
	"github.com/iden3/go-iden3-auth/loaders"
	core "github.com/iden3/go-iden3-core"
	jsonSuite "github.com/iden3/go-schema-processor/json"
	"github.com/iden3/go-schema-processor/merklize"
	"github.com/iden3/go-schema-processor/utils"
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
	AllowedIssuers string                 `json:"allowedIssuers"`
	Req            map[string]interface{} `json:"req,omitempty"`
	Context        string                 `json:"context"`
	Type           string                 `json:"type"`
	ClaimID        string                 `json:"claimId,omitempty"`
}

// AtomicPubSignals pub signals from circuit.
type AtomicPubSignals struct {
	IssuerID           *core.ID
	ClaimSchema        core.SchemaHash
	SlotIndex          int
	Operator           int
	Value              []*big.Int
	Timestamp          int64
	Merklized          int
	ClaimPathKey       *big.Int
	ClaimPathNotExists int
	ValueArraySize     int
}

func (q Query) validateIssuer(pubSig *AtomicPubSignals) error {
	// TODO(illia-korotia): should be list of issuers.
	if q.AllowedIssuers == "" || q.AllowedIssuers == "*" {
		return nil
	}
	if q.AllowedIssuers == pubSig.IssuerID.String() {
		return nil
	}
	return ErrUnavailableIssuer
}

func (q Query) validateSchemaID(pubSig *AtomicPubSignals) error {
	schemaID := fmt.Sprintf("%s#%s", q.Context, q.Type)
	querySchema := utils.CreateSchemaHash([]byte(schemaID))
	if querySchema.BigInt().Cmp(pubSig.ClaimSchema.BigInt()) == 0 {
		return nil
	}
	return ErrSchemaID
}

func (q Query) validatePredicate(pubSig *AtomicPubSignals) error {
	_, predicate, err := extractQueryFields(q.Req)
	if err != nil {
		return err
	}

	values, operator, err := parseFieldPredicate(predicate)
	if err != nil {
		return err
	}

	if operator == circuits.NOOP {
		return nil
	}
	if operator != pubSig.Operator {
		return ErrRequestOperator
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

// CheckRequest checks if proof was created for this request.
func (q Query) CheckRequest(ctx context.Context, loader loaders.SchemaLoader, pubSig *AtomicPubSignals) error {
	if err := q.validateIssuer(pubSig); err != nil {
		return err
	}

	if err := q.validateSchemaID(pubSig); err != nil {
		return err
	}

	if err := q.validatePredicate(pubSig); err != nil {
		return err
	}

	schemaBytes, _, err := loader.Load(ctx, q.Context)
	if err != nil {
		return fmt.Errorf("failed load schema by context: %w", err)
	}

	if pubSig.Merklized == 1 {
		return q.CheckMerklizedClaim(ctx, schemaBytes, pubSig)
	}
	return q.CheckNotMerklizedClaim(ctx, schemaBytes, pubSig)
}

// CheckMerklizedClaim match proof to request if proof is merklized.
func (q Query) CheckMerklizedClaim(_ context.Context, schemaBytes []byte, pubSig *AtomicPubSignals) error {
	if len(q.Req) == 0 {
		return nil
	}

	fieldName, _, err := extractQueryFields(q.Req)
	if err != nil {
		return err
	}

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
		return errors.New("proof doesn't contains target query kay")
	}

	return nil
}

// CheckNotMerklizedClaim check match proof to request if proof is NOT merklized.
func (q Query) CheckNotMerklizedClaim(_ context.Context, schemaBytes []byte, pubSig *AtomicPubSignals) error {
	pr := jsonSuite.Parser{}

	fieldName, _, err := extractQueryFields(q.Req)
	if err != nil {
		return err
	}

	slotIndex, err := pr.GetFieldSlotIndex(fieldName, schemaBytes)
	if err != nil {
		return err
	}

	if pubSig.SlotIndex != slotIndex {
		return errors.New("different slot index for claim")
	}

	return nil
}

func parseFieldPredicate(fieldPredicate map[string]interface{}) ([]*big.Int, int, error) {
	var (
		values   []*big.Int
		operator int
		err      error
	)

	for op, v := range fieldPredicate {

		var ok bool
		operator, ok = circuits.QueryOperators[op]
		if !ok {
			return nil, 0, errors.New("query operator is not supported")
		}

		values, err = getValuesAsArray(v)
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

func getValuesAsArray(v interface{}) ([]*big.Int, error) {
	var values []*big.Int

	switch value := v.(type) {
	case float64:
		values = make([]*big.Int, 1)
		values[0] = new(big.Int).SetInt64(int64(value))
	case []interface{}:
		values = make([]*big.Int, len(value))
		for i, item := range value {
			values[i] = new(big.Int).SetInt64(int64(item.(float64)))
		}
	default:
		return nil, errors.Errorf("unsupported values type %T", v)
	}

	return values, nil
}
