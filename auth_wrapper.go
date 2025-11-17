package auth

import (
	"context"
	"math/big"

	"github.com/iden3/driver-did-iden3/pkg/services"
	"github.com/iden3/go-iden3-auth/v2/pubsignals"
	core "github.com/iden3/go-iden3-core/v2"
	"github.com/iden3/go-iden3-core/v2/w3c"
	"github.com/pkg/errors"
)

type publicSignralResolverWrapper struct {
	chainID string
	pubsignals.StateResolver
}

func (p *publicSignralResolverWrapper) Resolve(ctx context.Context, did w3c.DID, opts *services.ResolverOpts) (services.IdentityState, error) {
	id, err := core.IDFromDID(did)
	if err != nil {
		return services.IdentityState{}, err
	}
	if opts.State == nil {
		return services.IdentityState{}, errors.New("state is required in resolver options")
	}

	rs, err := p.StateResolver.Resolve(ctx, id.BigInt(), opts.State)
	if err != nil {
		return services.IdentityState{}, err
	}

	s, ok := big.NewInt(0).SetString(rs.State, 10)
	if !ok {
		return services.IdentityState{}, errors.New("failed to convert state to big.Int")
	}
	rt := big.NewInt(rs.TransitionTimestamp)

	return services.IdentityState{
		StateInfo: &services.StateInfo{
			ID:                  did,
			State:               s,
			ReplacedAtTimestamp: rt,
		},
	}, nil
}

func (p *publicSignralResolverWrapper) ResolveGist(ctx context.Context, opts *services.ResolverOpts) (*services.GistInfo, error) {
	if opts.GistRoot == nil {
		return nil, errors.New("gist root is required in resolver options")
	}
	gr, err := p.StateResolver.ResolveGlobalRoot(ctx, opts.GistRoot)
	if err != nil {
		return nil, err
	}

	if gr.State == "" {
		gr.State = opts.GistRoot.String()
	}

	if !gr.Latest {
		if gr.TransitionTimestamp == 0 {
			return nil, errors.New("transition timestamp is zero for non-latest gist")
		}

		return &services.GistInfo{
			Root:                opts.GistRoot,
			ReplacedByRoot:      big.NewInt(1),                      // indicates that the gist is not latest
			ReplacedAtTimestamp: big.NewInt(gr.TransitionTimestamp), // pass real replacement time
		}, nil
	}

	r, ok := big.NewInt(0).SetString(gr.State, 10)
	if !ok {
		return nil, errors.New("failed to convert state to big.Int")
	}
	return &services.GistInfo{
		Root:                r,
		ReplacedAtTimestamp: big.NewInt(gr.TransitionTimestamp),
		ReplacedByRoot:      big.NewInt(0),
	}, nil
}

func (p *publicSignralResolverWrapper) BlockchainID() string {
	return p.chainID
}
