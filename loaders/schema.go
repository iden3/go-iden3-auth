package loaders

import (
	"context"
	"fmt"
	"net/url"

	"github.com/iden3/go-schema-processor/loaders"
	"github.com/iden3/go-schema-processor/processor"
)

// SchemaLoader is an interface for schema loading
type SchemaLoader interface {
	Load(ctx context.Context, URL string) (schemaBytes []byte, extension string, err error)
}

// DefaultSchemaLoader is loader defined by auth lib, but can be replaced with any custom loader
type DefaultSchemaLoader struct {
	IpfsURL string `json:"ipfs_url"`
}

// Load loads schema from IPFS or by http link
//
//nolint:gocritic // URL is correct name for variable that describes URL.
func (d DefaultSchemaLoader) Load(ctx context.Context, URL string) (schemaBytes []byte, extension string, err error) {
	var loader processor.SchemaLoader
	schemaURL, err := url.Parse(URL)
	if err != nil {
		return nil, "", err
	}
	switch schemaURL.Scheme {
	case "http", "https":
		loader = &loaders.HTTP{URL: URL}
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
