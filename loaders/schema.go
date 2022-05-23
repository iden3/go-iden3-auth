package loaders

import (
	"context"
	"fmt"
	"github.com/iden3/go-schema-processor/loaders"
	"github.com/iden3/go-schema-processor/processor"
	"github.com/iden3/iden3comm/protocol"
	"net/url"
)

// SchemaLoader is an interface for schema loading
type SchemaLoader interface {
	Load(ctx context.Context, schema protocol.Schema) (schemaBytes []byte, extension string, err error)
}

// DefaultSchemaLoader is loader defined by auth lib, but can be replaced with any custom loader
type DefaultSchemaLoader struct {
	IpfsURL string `json:"ipfs_url"`
}

// Load loads schema from IPFS or by http link
func (d DefaultSchemaLoader) Load(ctx context.Context, schema protocol.Schema) (schemaBytes []byte, extension string, err error) {
	var loader processor.SchemaLoader
	schemaURL, err := url.Parse(schema.URL)
	if err != nil {
		return nil, "", err
	}
	switch schemaURL.Scheme {
	case "http", "https":
		loader = &loaders.HTTP{URL: schema.URL}
	case "ipfs":
		loader = loaders.IPFS{
			URL: d.IpfsURL,
			CID: schemaURL.Host,
		}
	default:
		return nil, "", fmt.Errorf("loader for %s is not supported", schemaURL.Scheme)
	}
	return loader.Load(ctx)
}
