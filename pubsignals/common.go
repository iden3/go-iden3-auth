package pubsignals

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"

	"github.com/iden3/go-circuits/v2"
	"github.com/iden3/go-iden3-crypto/poseidon"
	parser "github.com/iden3/go-schema-processor/v2/json"
	"github.com/iden3/go-schema-processor/v2/merklize"
	"github.com/iden3/go-schema-processor/v2/verifiable"
	"github.com/piprate/json-gold/ld"
	"github.com/pkg/errors"
)

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

const credentialSubjectFullKey = "https://www.w3.org/2018/credentials#credentialSubject" // #nosec G101

// ParseCredentialSubject parse credential subject and return array of property queries
func ParseCredentialSubject(_ context.Context, credentialSubject any) (out []PropertyQuery, err error) {
	if credentialSubject == nil {
		return []PropertyQuery{
			{
				Operator:  circuits.NOOP,
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
		return []PropertyQuery{
			{
				Operator:  circuits.NOOP,
				FieldName: "",
			},
		}, nil
	}

	for fieldName, fieldReq := range jsonObject {
		fieldReqEntries, ok := fieldReq.(map[string]interface{})
		if !ok {
			return nil, errors.New("failed cast type map[string]interface")
		}
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

	query = &QueryMetadata{
		PropertyQuery:   propertyQuery,
		SlotIndex:       0,
		MerklizedSchema: false,
		Datatype:        "",
		ClaimPathKey:    big.NewInt(0),
		Values:          []*big.Int{},
		Path:            &merklize.Path{},
	}

	if query.FieldName != "" {
		query.Datatype, err = options.TypeFromContext([]byte(ldContextJSON), fmt.Sprintf("%s.%s", credentialType, propertyQuery.FieldName))
		if err != nil {
			return nil, err
		}
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

	serAttr, err := verifiable.GetSerializationAttrFromParsedContext(ldCtx, credentialType)
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
	}

	if propertyQuery.OperatorValue != nil && query.Datatype != "" {
		if !IsValidOperation(query.Datatype, propertyQuery.Operator) {
			operatorName, _ := getKeyByValue(circuits.QueryOperators, propertyQuery.Operator)
			return nil, fmt.Errorf("invalid operation '%s' for field type '%s'", operatorName, query.Datatype)
		}
	}

	query.Values, err = transformQueryValueToBigInts(ctx, propertyQuery.OperatorValue, query.Datatype)
	if err != nil {
		return nil, err
	}

	return query, err
}

// ParseQueriesMetadata parse credential subject and return array of query metadata
func ParseQueriesMetadata(ctx context.Context, credentialType, ldContextJSON string, credentialSubject map[string]interface{}, options merklize.Options) (out []QueryMetadata, err error) {
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
	if ldType == "" {
		return []*big.Int{}, nil
	}

	if value == nil {
		return make([]*big.Int, 0), nil
	}

	listOfValues, ok := value.([]interface{})
	if ok {
		out = make([]*big.Int, len(listOfValues))
		for i := 0; i < len(listOfValues); i++ {
			if !isPositiveInteger(listOfValues[i]) {
				return nil, ErrNegativeValue
			}
			out[i], err = merklize.HashValue(ldType, listOfValues[i])
			if err != nil {
				return nil, err
			}
		}
		return out, err
	}
	if !isPositiveInteger(value) {
		return nil, ErrNegativeValue
	}
	hashValue, err := merklize.HashValue(ldType, value)
	if err != nil {
		return nil, err
	}

	return []*big.Int{hashValue}, err
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

func getKeyByValue(m map[string]int, targetValue int) (string, bool) {
	for key, value := range m {
		if value == targetValue {
			return key, true
		}
	}
	return "", false
}

// CalculateQueryHash calculates query hash
func CalculateQueryHash(
	values []*big.Int,
	schemaHash *big.Int,
	slotIndex int,
	operator int,
	claimPathKey *big.Int,
	isMerklized bool,
) (*big.Int, error) {
	claimPathNotExists := big.NewInt(0)
	if operator == circuits.EXISTS && values[0].Cmp(new(big.Int)) == 0 {
		claimPathNotExists.SetInt64(1)
	}
	merklized := big.NewInt(0)
	if isMerklized {
		merklized.SetInt64(1)
	}

	valArrSize := big.NewInt(int64(len(values)))
	circuitValues, err := circuits.PrepareCircuitArrayValues(values, 64)
	if err != nil {
		return nil, err
	}

	valueHash, err := poseidon.SpongeHashX(circuitValues, 6)
	if err != nil {
		return nil, err
	}
	firstPart, err := poseidon.Hash([]*big.Int{
		schemaHash,
		big.NewInt(int64(slotIndex)),
		big.NewInt(int64(operator)),
		claimPathKey,
		claimPathNotExists,
		valueHash,
	})
	if err != nil {
		return nil, err
	}
	return poseidon.Hash([]*big.Int{
		firstPart,
		valArrSize,
		merklized,
		big.NewInt(0),
		big.NewInt(0),
		big.NewInt(0),
	})

}

func fieldValueFromVerifiablePresentation(ctx context.Context, verifiablePresentation json.RawMessage, schemaLoader ld.DocumentLoader, key string) (*big.Int, error) {
	if verifiablePresentation == nil {
		return nil, errors.New("selective disclosure value is missed")
	}

	mz, err := merklize.MerklizeJSONLD(ctx,
		bytes.NewBuffer(verifiablePresentation),
		merklize.WithDocumentLoader(schemaLoader))
	if err != nil {
		return nil, errors.Errorf("failed to merklize doc: %v", err)
	}

	merklizedPath, err := merklize.Options{DocumentLoader: schemaLoader}.
		NewPathFromDocument(verifiablePresentation,
			fmt.Sprintf("verifiableCredential.credentialSubject.%s", key))
	if err != nil {
		return nil, errors.Errorf("failed build path to '%s' key: %v", key, err)
	}

	proof, valueByPath, err := mz.Proof(ctx, merklizedPath)
	if err != nil {
		return nil, errors.Errorf("failed get raw value: %v", err)
	}
	if !proof.Existence {
		return nil, errors.Errorf("path '%v' doesn't exist in document", merklizedPath.Parts())
	}

	mvBig, err := valueByPath.MtEntry()
	if err != nil {
		return nil, errors.Errorf("failed to hash value: %v", err)
	}
	return mvBig, nil
}
