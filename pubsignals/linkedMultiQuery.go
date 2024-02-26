package pubsignals

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"sort"

	"github.com/iden3/go-circuits/v2"
	"github.com/iden3/go-schema-processor/v2/merklize"
	"github.com/iden3/go-schema-processor/v2/utils"
	"github.com/piprate/json-gold/ld"
	"github.com/pkg/errors"
)

// LinkedMultiQuery is a wrapper for circuits.LinkedMultiQueryPubSignals.
type LinkedMultiQuery struct {
	circuits.LinkedMultiQueryPubSignals
}

// VerifyQuery verifies query for linked multi query 10 circuit.
func (c *LinkedMultiQuery) VerifyQuery(
	ctx context.Context,
	query Query,
	schemaLoader ld.DocumentLoader,
	vp json.RawMessage,
	_ map[string]interface{},
	_ ...VerifyOpt,
) (CircuitVerificationResult, error) {
	var outputs CircuitVerificationResult
	schemaDoc, err := schemaLoader.LoadDocument(query.Context)
	if err != nil {
		return outputs, fmt.Errorf("failed load schema by context: %w", err)
	}

	schemaBytes, err := json.Marshal(schemaDoc.Document)
	if err != nil {
		return outputs, fmt.Errorf("failed jsonify schema document: %w", err)
	}

	schemaID, err := merklize.Options{DocumentLoader: schemaLoader}.
		TypeIDFromContext(schemaBytes, query.Type)
	if err != nil {
		return outputs, err
	}
	schemaHash := utils.CreateSchemaHash([]byte(schemaID))

	if schemaHash.BigInt() == nil {
		return outputs, fmt.Errorf("query schema error")
	}

	merkOption := merklize.Options{
		DocumentLoader: schemaLoader,
	}
	queriesMetadata, err := ParseQueriesMetadata(ctx, query.Type, string(schemaBytes), query.CredentialSubject, merkOption)
	if err != nil {
		return outputs, err
	}

	requests := []queryRequest{}
	querySignalsMeta := make(queriesMetaPubSignals, len(c.CircuitQueryHash))
	for i, q := range c.CircuitQueryHash {
		querySignalsMeta[i] = struct {
			OperatorOutput *big.Int
			QueryHash      *big.Int
		}{OperatorOutput: c.OperatorOutput[i], QueryHash: q}
	}

	merklized := false
	if len(queriesMetadata) > 0 && queriesMetadata[0].MerklizedSchema {
		merklized = true
	}
	for i := 0; i < circuits.LinkedMultiQueryLength; i++ {
		if i >= len(queriesMetadata) {
			queryHash, err := CalculateQueryHash(
				[]*big.Int{},
				schemaHash.BigInt(),
				0,
				0,
				big.NewInt(0),
				merklized)

			if err != nil {
				return outputs, err
			}

			requests = append(requests, struct {
				QueryMetadata *QueryMetadata
				QueryHash     *big.Int
			}{QueryMetadata: nil, QueryHash: queryHash})
			continue
		}

		queryHash, err := CalculateQueryHash(
			queriesMetadata[i].Values,
			schemaHash.BigInt(),
			queriesMetadata[i].SlotIndex,
			queriesMetadata[i].Operator,
			queriesMetadata[i].ClaimPathKey,
			merklized)

		if err != nil {
			return outputs, err
		}

		requests = append(requests, struct {
			QueryMetadata *QueryMetadata
			QueryHash     *big.Int
		}{QueryMetadata: &queriesMetadata[i], QueryHash: queryHash})
	}

	sortedPubsignalsMetadata := make(queriesMetaPubSignals, len(c.CircuitQueryHash))
	copy(sortedPubsignalsMetadata, querySignalsMeta)
	sort.Sort(sortedPubsignalsMetadata)

	sortedRequests := make(queryRequests, len(requests))
	copy(sortedRequests, requests)
	sort.Sort(sortedRequests)

	if sortedPubsignalsMetadata.Len() != sortedRequests.Len() {
		return outputs, fmt.Errorf("query hashes do not match")
	}

	for i := 0; i < sortedPubsignalsMetadata.Len(); i++ {
		if sortedPubsignalsMetadata[i].QueryHash.Cmp(sortedRequests[i].QueryHash) != 0 {
			return outputs, fmt.Errorf("query hashes do not match")
		}

		if sortedRequests[i].QueryMetadata != nil && sortedRequests[i].QueryMetadata.Operator == circuits.SD {
			disclosedValue, err2 := fieldValueFromVerifiablePresentation(ctx, vp, schemaLoader, sortedRequests[i].QueryMetadata.FieldName)
			if err2 != nil {
				return outputs, err2
			}
			if disclosedValue.Cmp(sortedPubsignalsMetadata[i].OperatorOutput) != 0 {
				return outputs, errors.New("disclosed value is not in the proof outputs")

			}
		}

	}

	outputs = CircuitVerificationResult{
		LinkID: c.LinkID,
	}

	return outputs, nil
}

type queryRequest struct {
	QueryMetadata *QueryMetadata
	QueryHash     *big.Int
}
type queryMetaPubSignals struct {
	OperatorOutput *big.Int
	QueryHash      *big.Int
}
type queriesMetaPubSignals []queryMetaPubSignals

func (q queriesMetaPubSignals) Len() int           { return len(q) }
func (q queriesMetaPubSignals) Swap(i, j int)      { q[i], q[j] = q[j], q[i] }
func (q queriesMetaPubSignals) Less(i, j int) bool { return q[i].QueryHash.Cmp(q[j].QueryHash) < 0 }

type queryRequests []queryRequest

func (q queryRequests) Len() int           { return len(q) }
func (q queryRequests) Swap(i, j int)      { q[i], q[j] = q[j], q[i] }
func (q queryRequests) Less(i, j int) bool { return q[i].QueryHash.Cmp(q[j].QueryHash) < 0 }

// VerifyStates verifies user state and issuer auth claim state in the smart contract.
func (c *LinkedMultiQuery) VerifyStates(_ context.Context, _ map[string]StateResolver, _ ...VerifyOpt) error {
	return nil
}

// VerifyIDOwnership returns error if ownership id wasn't verified in circuit.
func (c *LinkedMultiQuery) VerifyIDOwnership(_ string, _ *big.Int) error {
	return nil
}
