package pubsignals

import (
	"context"
	"math/big"

	"github.com/iden3/go-circuits"
	"github.com/iden3/go-iden3-auth/loaders"
	core "github.com/iden3/go-iden3-core"
	jsonSuite "github.com/iden3/go-schema-processor/json"
	jsonldSuite "github.com/iden3/go-schema-processor/json-ld"
	"github.com/iden3/go-schema-processor/processor"
	"github.com/iden3/go-schema-processor/utils"
	"github.com/iden3/iden3comm/protocol"
	"github.com/pkg/errors"
)

const (
	jsonldExt string = "json-ld"
	jsonExt   string = "json"
)

// Query represents structure for query to atomic circuit
type Query struct {
	AllowedIssuers []string               `json:"allowedIssuers"`
	Req            map[string]interface{} `json:"req"`
	Schema         protocol.Schema        `json:"schema"`
	ClaimID        string                 `json:"claimId,omitempty"`
}

// ClaimOutputs fields that are used in proof generation
type ClaimOutputs struct {
	IssuerID   *core.ID
	SchemaHash core.SchemaHash
	SlotIndex  int
	Operator   int
	Value      []*big.Int
}

// CheckRequest checks request
func (q Query) CheckRequest(ctx context.Context, loader loaders.SchemaLoader,
	out ClaimOutputs) error {

	if !verifyIssuer(q, out) {
		return errors.New("issuer is not in allowed list")
	}

	schemaBytes, ext, err := loader.Load(ctx, q.Schema)
	if err != nil {
		return errors.Wrap(err, "can't load schema for request query")
	}

	sh := utils.CreateSchemaHash(schemaBytes, q.Schema.Type)
	if sh.BigInt().Cmp(out.SchemaHash.BigInt()) != 0 {
		return errors.New("schema that was used is not equal to requested in query")
	}

	pr, err := prepareProcessor(q.Schema.Type, ext)
	if err != nil {
		return errors.Wrap(err, "can't prepare processor for request query")
	}

	queryReq, err := parseRequest(q.Req, schemaBytes, pr)
	if err != nil {
		return errors.Wrap(err, "can't parse request query")
	}

	return verifyQuery(queryReq, out)
}

func verifyIssuer(q Query, out ClaimOutputs) bool {
	issuerAllowed := false
	for _, i := range q.AllowedIssuers {
		if i == "*" || i == out.IssuerID.String() {
			issuerAllowed = true
			break
		}
	}
	return issuerAllowed
}

func verifyQuery(query *circuits.Query, out ClaimOutputs) error {

	if query.Operator != out.Operator {
		return errors.New("operator that was used is not equal to requested in query")
	}

	if query.Operator == circuits.NOOP { // circuits.NOOP slot and value are not used in this case
		return nil
	}

	if query.SlotIndex != out.SlotIndex {
		return errors.New("wrong claim slot was used in claim")
	}

	// add zeros, to check that out.Value[n] is also zero and not specific value.
	for len(query.Values) < len(out.Value) {
		query.Values = append(query.Values, big.NewInt(0))
	}

	for i, v := range query.Values {
		if v.Cmp(out.Value[i]) != 0 {
			return errors.New("comparison value that was used is not equal to requested in query")
		}
	}
	return nil
}

func prepareProcessor(claimType, ext string) (*processor.Processor, error) {
	pr := &processor.Processor{}
	var parser processor.Parser
	switch ext {
	case jsonExt:
		parser = jsonSuite.Parser{ParsingStrategy: processor.OneFieldPerSlotStrategy}
	case jsonldExt:
		parser = jsonldSuite.Parser{ClaimType: claimType, ParsingStrategy: processor.OneFieldPerSlotStrategy}
	default:
		return nil, errors.Errorf(
			"process suite for schema format %s is not supported", ext)
	}
	return processor.InitProcessorOptions(pr, processor.WithParser(parser)), nil
}

func parseRequest(req map[string]interface{}, schema []byte, pr *processor.Processor) (*circuits.Query, error) {

	if req == nil {
		return &circuits.Query{
			SlotIndex: 0,
			Values:    nil,
			Operator:  circuits.NOOP,
		}, nil
	}

	fieldName, fieldPredicate, err := extractQueryFields(req)
	if err != nil {
		return nil, err
	}

	values, operator, err := parseFieldPredicate(fieldPredicate, err)
	if err != nil {
		return nil, err
	}

	slotIndex, err := pr.GetFieldSlotIndex(fieldName, schema)
	if err != nil {
		return nil, err
	}

	return &circuits.Query{SlotIndex: slotIndex, Values: values, Operator: operator}, nil

}

func parseFieldPredicate(fieldPredicate map[string]interface{}, err error) ([]*big.Int, int, error) {
	var values []*big.Int
	var operator int
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
	return values, operator, err
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
