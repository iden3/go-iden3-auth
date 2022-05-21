package pubsignals

import (
	"context"
	"fmt"
	"github.com/iden3/go-circuits"
	core "github.com/iden3/go-iden3-core"
	jsonld2 "github.com/iden3/go-schema-processor/json-ld"
	"github.com/iden3/go-schema-processor/loaders"
	"github.com/iden3/go-schema-processor/processor"
	jsonld "github.com/iden3/go-schema-processor/processor/json-ld"
	"github.com/iden3/go-schema-processor/utils"
	"github.com/iden3/iden3comm/protocol"
	"github.com/pkg/errors"
	"math/big"
	"net/url"
)

// Query represents structure for query to atomic circuit
type Query struct {
	AllowedIssuers []string               `json:"allowed_issuers"`
	Req            map[string]interface{} `json:"req"`
	Schema         protocol.Schema        `json:"schema"`
	ClaimID        string                 `json:"claimId,omitempty"`
}

// CheckRequest checks request
func (q Query) CheckRequest(ctx context.Context, issuer *core.ID, schemaHash core.SchemaHash, slotIndex int, value []*big.Int, operator int) error {

	issuerAllowed := false
	for _, i := range q.AllowedIssuers {
		if i == "*" || i == issuer.String() {
			issuerAllowed = true
			break
		}
	}
	if !issuerAllowed {
		return errors.New("issuer is not in allowed list")
	}

	// load schema, because we need to calculate SchemaHash and get slot index for field in the request.
	var loader processor.SchemaLoader
	schemaURL, err := url.Parse(q.Schema.URL)
	if err != nil {
		return err
	}
	switch schemaURL.Scheme {
	case "http", "https":
		loader = &loaders.HTTP{URL: q.Schema.URL}
	case "ipfs":
		loader = loaders.IPFS{
			URL: "ipfs.io",
			CID: schemaURL.Host,
		}
	default:
		return fmt.Errorf("loader for %s is not supported", schemaURL.Scheme)
	}
	var schemaBytes []byte
	if err != nil {
		return err
	}

	p := jsonld.New(processor.WithSchemaLoader(loader), processor.WithParser(jsonld2.Parser{
		ClaimType:       q.Schema.Type,
		ParsingStrategy: processor.OneFieldPerSlotStrategy,
	}))
	if err != nil {
		return err
	}
	schemaBytes, _, err = p.Load(ctx)
	if err != nil {
		return errors.New("can't load the schema")
	}
	sh := utils.CreateSchemaHash(schemaBytes, q.Schema.Type)

	queryReq, err := parseRequest(q.Req, schemaBytes, p.Processor, len(value))
	if err != nil {
		return errors.Wrap(err, "can't parse request query")
	}
	if queryReq.Operator != operator {
		return errors.New("operator that was used is not equal to requested in query")
	}
	if queryReq.SlotIndex != slotIndex {
		return errors.New("wrong claim slot was used in claim")
	}
	for i, v := range queryReq.Values {
		if v.Cmp(value[i]) != 0 {
			return errors.New(" comparison value that was used is not equal to requested in query")
		}
	}

	if sh.BigInt().Cmp(schemaHash.BigInt()) != 0 {
		return errors.New("schema that was used is not equal to requested in query")
	}
	return nil
}

func parseRequest(req map[string]interface{}, schema []byte, pr processor.Processor, expectedValueSize int) (circuits.Query, error) {
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
