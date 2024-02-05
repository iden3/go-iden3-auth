package pubsignals

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"reflect"

	"github.com/iden3/go-circuits/v2"
	parser "github.com/iden3/go-schema-processor/v2/json"
	"github.com/iden3/go-schema-processor/v2/merklize"
	"github.com/piprate/json-gold/ld"
	"github.com/pkg/errors"
)

// todo: move & reuse to/from go-schem-processor

// PropertyQuery struct
type PropertyQuery struct {
	FieldName     string
	Operator      int
	OperatorValue any
}

// QueryMetadata struct describe query metadata
type QueryMetadata struct {
	PropertyQuery
	SlotIndex       int
	Values          []*big.Int
	Path            *merklize.Path
	ClaimPathKey    *big.Int
	Datatype        string
	MerklizedSchema bool
}

const (
	contextFullKey           = "@context"
	serializationFullKey     = "iden3_serialization"
	credentialSubjectFullKey = "https://www.w3.org/2018/credentials#credentialSubject" // #nosec G101
)

// ParseCredentialSubject parse credential subject and return array of property queries
func ParseCredentialSubject(_ context.Context, credentialSubject any) (out []PropertyQuery, err error) {
	if credentialSubject == nil {
		return []PropertyQuery{
			{
				Operator:  circuits.EQ,
				FieldName: "",
			},
		}, nil
	}

	out = []PropertyQuery{}

	jsonObject, ok := credentialSubject.(map[string]interface{})
	if !ok {
		return nil, errors.New("Failed to convert credential subject to JSONObject")
	}

	if len(jsonObject) == 0 {
		return nil, errors.New("query must have at least 1 predicate")
	}
	for fieldName, fieldReq := range jsonObject {
		fieldReqEntries := fieldReq.(map[string]interface{})
		isSelectiveDisclosure := len(fieldReqEntries) == 0

		if isSelectiveDisclosure {
			out = append(out, PropertyQuery{Operator: circuits.SD, FieldName: fieldName})
			continue
		}

		for operatorName, operatorValue := range fieldReqEntries {
			if _, exists := circuits.QueryOperators[operatorName]; !exists {
				return nil, errors.New("operator is not supported by lib")
			}
			operator := circuits.QueryOperators[operatorName]
			out = append(out, PropertyQuery{Operator: operator, FieldName: fieldName, OperatorValue: operatorValue})
		}
	}

	return out, nil
}

// ParseQueryMetadata parse property query and return query metadata
func ParseQueryMetadata(ctx context.Context, propertyQuery PropertyQuery, ldContextJSON, credentialType string, options merklize.Options) (query *QueryMetadata, err error) {
	datatype, err := options.TypeFromContext([]byte(ldContextJSON), fmt.Sprintf("%s.%s", credentialType, propertyQuery.FieldName))
	if err != nil {
		return nil, err
	}

	query = &QueryMetadata{
		PropertyQuery:   propertyQuery,
		SlotIndex:       0,
		MerklizedSchema: false,
		Datatype:        datatype,
		ClaimPathKey:    big.NewInt(0),
		Values:          []*big.Int{},
		Path:            &merklize.Path{},
	}

	var ctxObj map[string]interface{}
	err = json.Unmarshal([]byte(ldContextJSON), &ctxObj)
	if err != nil {
		return nil, err
	}

	ldCtx, err := ld.NewContext(nil, nil).Parse(ctxObj["@context"])
	if err != nil {
		return nil, err
	}

	serAttr, err := getSerializationAttrFromParsedContext(ldCtx, credentialType)
	if err != nil {
		return nil, err
	}
	if serAttr == "" {
		query.MerklizedSchema = true
	}

	if !query.MerklizedSchema {
		query.SlotIndex, err = parser.Parser{}.GetFieldSlotIndex(propertyQuery.FieldName, credentialType, []byte(ldContextJSON))
		if err != nil {
			return nil, err
		}
	} else {
		path := merklize.Path{}
		if query.FieldName != "" {
			path, err = options.FieldPathFromContext([]byte(ldContextJSON), credentialType, propertyQuery.FieldName)
			if err != nil {
				return nil, err
			}
		}

		err = path.Prepend(credentialSubjectFullKey)
		if err != nil {
			return nil, err
		}

		query.ClaimPathKey, err = path.MtEntry()
		if err != nil {
			return nil, err
		}
		query.Path = &path

		if propertyQuery.OperatorValue != nil {
			if !IsValidOperation(datatype, propertyQuery.Operator) {
				return nil, fmt.Errorf("operator %d is not supported for datatype %s", propertyQuery.Operator, datatype)
			}
		}

		query.Values, err = transformQueryValueToBigInts(ctx, propertyQuery.OperatorValue, datatype)
		if err != nil {
			return nil, err
		}
	}

	return query, err
}

// ParseQueriesMetadata parse credential subject and return array of query metadata
func ParseQueriesMetadata(ctx context.Context, credentialType, ldContextJSON string, credentialSubject any, options merklize.Options) (out []QueryMetadata, err error) {
	queriesMetadata, err := ParseCredentialSubject(ctx, credentialSubject)
	if err != nil {
		return nil, err
	}
	out = []QueryMetadata{}
	for i := 0; i < len(queriesMetadata); i++ {
		queryMetadata, err := ParseQueryMetadata(ctx, queriesMetadata[i], ldContextJSON, credentialType, options)
		if err != nil {
			return nil, err
		}
		out = append(out, *queryMetadata)
	}
	return out, err
}

func transformQueryValueToBigInts(_ context.Context, value any, ldType string) (out []*big.Int, err error) {
	out = make([]*big.Int, 64)
	for i := 0; i < 64; i++ {
		out[i] = big.NewInt(0)
	}

	if reflect.TypeOf(value).Kind() == reflect.Array {
		v := reflect.ValueOf(value)
		for i := 0; i < v.Len(); i++ {
			out[i], err = merklize.HashValue(ldType, v.Index(i).Interface())
			if err != nil {
				return nil, err
			}
		}
	} else {
		out[0], err = merklize.HashValue(ldType, value)
		if err != nil {
			return nil, err
		}
	}
	return out, err
}

// todo: exists in go-schem-processor (private)
func getSerializationAttrFromParsedContext(ldCtx *ld.Context,
	tp string) (string, error) {

	termDef, ok := ldCtx.AsMap()["termDefinitions"]
	if !ok {
		return "", errors.New("types now found in context")
	}

	termDefM, ok := termDef.(map[string]any)
	if !ok {
		return "", errors.New("terms definitions is not of correct type")
	}

	for typeName, typeDef := range termDefM {
		typeDefM, ok := typeDef.(map[string]any)
		if !ok {
			// not a type
			continue
		}
		typeCtx, ok := typeDefM[contextFullKey]
		if !ok {
			// not a type
			continue
		}
		typeCtxM, ok := typeCtx.(map[string]any)
		if !ok {
			return "", errors.New("type @context is not of correct type")
		}
		typeID, _ := typeDefM["@id"].(string)
		if typeName != tp && typeID != tp {
			continue
		}

		serStr, _ := typeCtxM[serializationFullKey].(string)
		return serStr, nil
	}

	return "", nil
}