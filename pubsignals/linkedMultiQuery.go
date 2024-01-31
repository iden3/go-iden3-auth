package pubsignals

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"sort"

	"github.com/iden3/go-circuits/v2"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/iden3/go-schema-processor/v2/merklize"
	"github.com/iden3/go-schema-processor/v2/utils"
	"github.com/piprate/json-gold/ld"
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
	_ json.RawMessage,
	_ map[string]interface{},
	_ ...VerifyOpt,
) (CircuitOutputs, error) {
	var outputs CircuitOutputs
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

	queryHashes := []*big.Int{}
	for i := 0; i < circuits.LinkedMultiQueryLength; i++ {
		if i >= len(queriesMetadata) {
			queryHashes = append(queryHashes, big.NewInt(0))
			continue
		}
		valueHash, err := poseidon.SpongeHashX(queriesMetadata[i].Values, 6)
		if err != nil {
			return outputs, err
		}

		merklizedSchema := big.NewInt(0)
		if !queriesMetadata[i].MerklizedSchema {
			merklizedSchema = big.NewInt(0)
		}
		queryHash, err := poseidon.Hash([]*big.Int{
			schemaHash.BigInt(),
			big.NewInt(int64(queriesMetadata[i].SlotIndex)),
			big.NewInt(int64(queriesMetadata[i].Operator)),
			queriesMetadata[i].ClaimPathKey,
			merklizedSchema,
			valueHash,
		})
		if err != nil {
			return outputs, err
		}

		queryHashes = append(queryHashes, queryHash)
	}

	var circuitQueryHashArray BigIntArray = make(BigIntArray, len(c.CircuitQueryHash))
	copy(circuitQueryHashArray, c.CircuitQueryHash)
	sort.Sort(circuitQueryHashArray)

	var calcQueryHashArray BigIntArray = make(BigIntArray, len(queryHashes))
	copy(calcQueryHashArray, queryHashes)
	sort.Sort(calcQueryHashArray)

	if circuitQueryHashArray.Len() != calcQueryHashArray.Len() {
		return outputs, fmt.Errorf("query hashes do not match")
	}

	for i := 0; i < circuitQueryHashArray.Len(); i++ {
		if circuitQueryHashArray[i].Cmp(calcQueryHashArray[i]) != 0 {
			return outputs, fmt.Errorf("query hashes do not match")
		}
	}

	outputs = CircuitOutputs{
		LinkID:    c.LinkID,
		Merklized: c.Merklized,
	}

	return outputs, nil
}

type BigIntArray []*big.Int

func (a BigIntArray) Len() int           { return len(a) }
func (a BigIntArray) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a BigIntArray) Less(i, j int) bool { return a[i].Cmp(a[j]) < 0 }

// VerifyStates verifies user state and issuer auth claim state in the smart contract.
func (c *LinkedMultiQuery) VerifyStates(_ context.Context, _ map[string]StateResolver, _ ...VerifyOpt) error {
	return nil
}

// VerifyIDOwnership returns error if ownership id wasn't verified in circuit.
func (c *LinkedMultiQuery) VerifyIDOwnership(_ string, _ *big.Int) error {
	return nil
}
