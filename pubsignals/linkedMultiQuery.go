package pubsignals

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"

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
	verifiablePresentation json.RawMessage,
	params map[string]interface{},
	opts ...VerifyOpt,
) error {
	schemaDoc, err := schemaLoader.LoadDocument(query.Context)
	if err != nil {
		return fmt.Errorf("failed load schema by context: %w", err)
	}

	schemaBytes, err := json.Marshal(schemaDoc.Document)
	if err != nil {
		return fmt.Errorf("failed jsonify schema document: %w", err)
	}

	schemaID, err := merklize.Options{DocumentLoader: schemaLoader}.
		TypeIDFromContext(schemaBytes, query.Type)
	if err != nil {
		return err
	}
	schemaHash := utils.CreateSchemaHash([]byte(schemaID))

	if schemaHash.BigInt() == nil {
		return fmt.Errorf("query schema error")
	}

	merkOption := merklize.Options{
		DocumentLoader: schemaLoader,
	}
	queriesMetadata, err := ParseQueriesMetadata(ctx, query.Type, string(schemaBytes), query.CredentialSubject, merkOption)
	if err != nil {
		return err
	}

	for i := 0; i < len(queriesMetadata); i++ {
		valueHash, err := poseidon.SpongeHashX(queriesMetadata[i].Values, 6)
		if err != nil {
			return err
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

		if c.CircuitQueryHash[i].Cmp(queryHash) != 0 {
			return fmt.Errorf("query hashes do not match")
		}
	}

	return nil
}

// VerifyStates verifies user state and issuer auth claim state in the smart contract.
func (c *LinkedMultiQuery) VerifyStates(ctx context.Context, stateResolvers map[string]StateResolver, opts ...VerifyOpt) error {
	return nil
}

// VerifyIDOwnership returns error if ownership id wasn't verified in circuit.
func (c *LinkedMultiQuery) VerifyIDOwnership(sender string, requestID *big.Int) error {
	return nil
}
