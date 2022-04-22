package verification

import (
	"math/big"

	"github.com/pkg/errors"
)

type State struct {
	*big.Int
}

func (s *State) Unmarshal(data []interface{}) error {
	if len(data) == 0 {
		return errors.New("invalid data")
	}
	if data[0] == nil {
		return errors.New("invalid data")
	}
	bi, ok := data[0].(*big.Int)
	if !ok {
		return errors.New("failed unmarshal to big.Int")
	}
	s.Int = bi

	return nil
}

type TransitionInfo struct {
	ReplacedAtTimestamp *big.Int
	CreatedAtTimestamp  *big.Int
	ReplacedAtBlock     uint64
	CreatedAtBlock      uint64
	ID                  *big.Int
	ReplacedBy          *big.Int
}

func (ti *TransitionInfo) Unmarshal(data []interface{}) error {
	if len(data) < 6 {
		return errors.New("invalid data")
	}
	for i, v := range data {
		if v == nil {
			return errors.Errorf("invalid values in %d position", i)
		}
	}
	// TODO (illia-korotia): move to reflect or/and code generation.
	bi, ok := data[0].(*big.Int)
	if !ok {
		return errors.Errorf("failed unmarshal to big.Int in position %d", 0)
	}
	ti.ReplacedAtTimestamp = bi

	bi, ok = data[1].(*big.Int)
	if !ok {
		return errors.Errorf("failed unmarshal to big.Int in position %d", 1)
	}
	ti.CreatedAtTimestamp = bi

	u, ok := data[2].(uint64)
	if !ok {
		return errors.Errorf("failed unmarshal to uint64 in position %d", 2)
	}
	ti.ReplacedAtBlock = u

	u, ok = data[3].(uint64)
	if !ok {
		return errors.Errorf("failed unmarshal to uint64 in position %d", 3)
	}
	ti.CreatedAtBlock = u

	bi, ok = data[4].(*big.Int)
	if !ok {
		return errors.Errorf("failed unmarshal to big.Int in position %d", 4)
	}
	ti.ID = bi

	bi, ok = data[5].(*big.Int)
	if !ok {
		return errors.Errorf("failed unmarshal to big.Int in position %d", 5)
	}
	ti.ReplacedBy = bi

	return nil
}
