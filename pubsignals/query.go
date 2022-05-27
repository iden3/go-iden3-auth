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
	AllowedIssuers []string               `json:"allowed_issuers"`
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

	pr := &processor.Processor{}
	var parser processor.Parser
	switch ext {
	case jsonExt:
		parser = jsonSuite.Parser{ParsingStrategy: processor.OneFieldPerSlotStrategy}
	case jsonldExt:
		parser = jsonldSuite.Parser{ClaimType: q.Schema.Type, ParsingStrategy: processor.OneFieldPerSlotStrategy}
	default:
		return errors.Errorf(
			"process suite for schema format %s is not supported", ext)
	}
	pr = processor.InitProcessorOptions(pr, processor.WithParser(parser))

	queryReq, err := parseRequest(q.Req, schemaBytes, pr, len(out.Value))
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

func verifyQuery(query circuits.Query, out ClaimOutputs) error {

	if query.Operator == out.Operator && query.Operator == circuits.NOOP {
		return nil
	}

	if query.Operator != out.Operator {
		return errors.New("operator that was used is not equal to requested in query")
	}
	if query.SlotIndex != out.SlotIndex {
		return errors.New("wrong claim slot was used in claim")
	}
	for i, v := range query.Values {
		if v.Cmp(out.Value[i]) != 0 {
			return errors.New("comparison value that was used is not equal to requested in query")
		}
	}
	return nil
}

func parseRequest(req map[string]interface{}, schema []byte, pr *processor.Processor, expectedValueSize int) (circuits.Query, error) {

	if req == nil {
		return circuits.Query{
			SlotIndex: 0,
			Values:    nil,
			Operator:  circuits.NOOP,
		}, nil
	}

	if len(req) > 1 {
		return circuits.Query{}, errors.New("multiple requests  not supported")
	}
	var fieldName string
	var fieldPredicate map[string]interface{}
	for field, body := range req {
		fieldName = field
		var ok bool
		fieldPredicate, ok = body.(map[string]interface{})
		if !ok {
			return circuits.Query{}, errors.New("failed cast type map[string]interface")
		}
		if len(fieldPredicate) > 1 {
			return circuits.Query{}, errors.New("multiple predicates for one field not supported")
		}
		break
	}
	slotIndex, err := pr.GetFieldSlotIndex(fieldName, schema)

	if err != nil {
		return circuits.Query{}, err
	}
	var values []*big.Int
	var operator int
	for op, v := range fieldPredicate {

		var ok bool
		operator, ok = circuits.QueryOperators[op]
		if !ok {
			return circuits.Query{}, errors.New("query operator is not supported")
		}

		values, err = getValuesAsArray(v, expectedValueSize)
		if err != nil {
			return circuits.Query{}, err
		}
		// only one predicate for field is supported
		break
	}
	return circuits.Query{SlotIndex: slotIndex, Values: values, Operator: operator}, nil

}

func getValuesAsArray(v interface{}, size int) ([]*big.Int, error) {
	values := make([]*big.Int, size)
	for i := range values {
		values[i] = big.NewInt(0)
	}

	switch value := v.(type) {
	case float64:
		values[0] = new(big.Int).SetInt64(int64(value))
	case []interface{}:
		if len(value) > size {
			return nil, errors.Errorf("array size {%d} is bigger max expected size {%d}",
				len(value), size)
		}
		for i, item := range value {
			values[i] = new(big.Int).SetInt64(int64(item.(float64)))
		}
	default:
		return nil, errors.Errorf("unsupported values type %T", v)
	}

	return values, nil
}
