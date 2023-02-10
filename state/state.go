package state

import (
	"context"
	"math/big"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	core "github.com/iden3/go-iden3-core"
	"github.com/pkg/errors"
)

var zero = big.NewInt(0)

const (
	gistNotFoundException  = "execution reverted: Root does not exist"
	stateNotFoundException = "execution reverted: State does not exist"
)

// VerificationOptions is options for state verification
type VerificationOptions struct {
	Contract string
	RPCUrl   string
}

// ExtendedVerificationsOptions allows to set additional options
type ExtendedVerificationsOptions struct {
	VerificationOptions
	OnlyLatestStates             bool
	AcceptedStateTransitionDelay time.Duration
}

// StateGetter return user's state info by user's ID
//
//go:generate mockgen -destination=mock/StateGetterMock.go . StateGetter
//nolint:revive // we have two different getters for the state in one pkg
type StateGetter interface {
	GetStateInfoByState(opts *bind.CallOpts, state *big.Int) (StateV2StateInfo, error)
}

// GISTGetter return global state info by state
//
//go:generate mockgen -destination=mock/GISTGetterMock.go . GISTGetter
type GISTGetter interface {
	GetGISTRootInfo(opts *bind.CallOpts, state *big.Int) (SmtRootInfo, error)
}

// ResolvedState can be the state verification result
type ResolvedState struct {
	State               string `json:"state"`
	Latest              bool   `json:"latest"`
	Genesis             bool   `json:"genesis"`
	TransitionTimestamp int64  `json:"transition_timestamp"`
}

// Resolve is used to resolve identity state.
func Resolve(ctx context.Context, getter StateGetter, id, state *big.Int) (*ResolvedState, error) {
	// сheck if id is genesis  - then we do need to resolve it.
	isGenesis, err := CheckGenesisStateID(id, state)
	if err != nil {
		return nil, err
	}

	stateInfo, err := getter.GetStateInfoByState(&bind.CallOpts{Context: ctx}, state)
	if err != nil && strings.Contains(err.Error(), stateNotFoundException) {
		if isGenesis {
			return &ResolvedState{Latest: true, Genesis: isGenesis, State: state.String()}, nil
		}
		return nil, errors.New("state is not genesis and not registered in the smart contract")
	} else if err != nil {
		return nil, err
	}

	if stateInfo.Id.Cmp(id) != 0 {
		return nil, errors.New("state has been saved for a different ID")
	}

	if stateInfo.ReplacedAtTimestamp.Cmp(zero) == 0 {
		return &ResolvedState{Latest: true, Genesis: isGenesis, State: state.String()}, nil
	}

	return &ResolvedState{
		Latest:              false,
		Genesis:             isGenesis,
		State:               state.String(),
		TransitionTimestamp: stateInfo.ReplacedAtTimestamp.Int64(),
	}, nil
}

// ResolveGlobalRoot is used to resolve global root.
func ResolveGlobalRoot(ctx context.Context, getter GISTGetter, state *big.Int) (*ResolvedState, error) {
	globalStateInfo, err := getter.GetGISTRootInfo(&bind.CallOpts{Context: ctx}, state)
	if err != nil && strings.Contains(err.Error(), gistNotFoundException) {
		return nil, errors.New("gist state doesn't exist on smart contract")
	} else if err != nil {
		return nil, err
	}

	if globalStateInfo.Root.Cmp(state) != 0 {
		return nil, errors.New("gist info contains invalid state")
	}
	if globalStateInfo.ReplacedByRoot.Cmp(zero) != 0 {
		if globalStateInfo.ReplacedAtTimestamp.Cmp(zero) == 0 {
			return nil, errors.New("state was replaced, but replaced time unknown")
		}
		return &ResolvedState{
			State:               state.String(),
			Latest:              false,
			TransitionTimestamp: globalStateInfo.ReplacedAtTimestamp.Int64(),
		}, nil
	}
	return &ResolvedState{
		State:               state.String(),
		Latest:              true,
		TransitionTimestamp: 0,
	}, nil
}

// CheckGenesisStateID check if the state is genesis for the id.
func CheckGenesisStateID(id, state *big.Int) (bool, error) {
	userID, err := core.IDFromInt(id)
	if err != nil {
		return false, err
	}
	identifier, err := core.IdGenesisFromIdenState(userID.Type(), state)
	if err != nil {
		return false, err
	}

	return id.Cmp(identifier.BigInt()) == 0, nil
}
