package pubsignals

import (
	"context"
	"fmt"
	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-schema-processor/loaders"
	"github.com/iden3/go-schema-processor/processor"
	"github.com/iden3/go-schema-processor/utils"
	"github.com/iden3/iden3comm/protocol"
	"github.com/pkg/errors"
	"net/url"
)

// Query represents structure for query to atomic circuit
type Query struct {
	AllowedIssuers []string
	Req            map[string]interface{}
	Schema         protocol.Schema
	ClaimID        string `json:"claimId,omitempty"`
}

// CheckIssuer verifies claim issuer
func (q Query) CheckIssuer(identifier string) bool {
	if len(q.AllowedIssuers) == 1 && q.AllowedIssuers[0] == "*" {
		return true
	}
	for _, i := range q.AllowedIssuers {
		if i == identifier {
			return true
		}
	}
	return false
}

// CheckSchema verifies claim schema
func (q Query) CheckSchema(ctx context.Context, schemaHash core.SchemaHash) error {
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
			URL: "ipfs.io/",
			CID: schemaURL.Host,
		}
	default:
		return fmt.Errorf("loader for %s is not supported", schemaURL.Scheme)
	}
	var schemaBytes []byte
	schemaBytes, _, err = loader.Load(ctx)
	if err != nil {
		return err
	}
	sh := utils.CreateSchemaHash(schemaBytes, q.Schema.Type)

	if sh.BigInt().Cmp(schemaHash.BigInt()) != 0 {
		return errors.New("schema that was used is not equal to requested in query")
	}
	return nil
}
