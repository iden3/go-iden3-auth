package verification

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestState(t *testing.T)  {
	type testCase struct{
		name string
		data []interface{}
		result *State
		error error
	}

	tests := []testCase{
		{
			name: "Success parse response",
			data: []interface{}{big.NewInt(1)},
			result: &State{big.NewInt(1)},
			error: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := new(State)
			err := s.Unmarshal(tt.data)
			if tt.error != nil {
				require.EqualError(t, err, tt.error.Error())
			}
			require.Equal(t, tt.result, s)
			require.NoError(t, err)
		})
	}
}

func TestTransitionInfo(t *testing.T) {
	type testCase struct{
		name string
		data []interface{}
		result *TransitionInfo
		error error
	}

	tests := []testCase{
		{
			name: "Success parse response",
			data: []interface{}{big.NewInt(1),big.NewInt(1), uint64(11), uint64(12), big.NewInt(1), big.NewInt(1)},
			result: &TransitionInfo{
				ReplacedAtTimestamp: big.NewInt(1),
				CreatedAtTimestamp: big.NewInt(1),
				ReplacedAtBlock: uint64(11),
				CreatedAtBlock: uint64(12),
				ReplacedBy: big.NewInt(1),
				ID: big.NewInt(1),
			},
			error: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := new(TransitionInfo)
			err := s.Unmarshal(tt.data)
			if tt.error != nil {
				require.EqualError(t, err, tt.error.Error())
			}
			require.Equal(t, tt.result, s)
			require.NoError(t, err)
		})
	}
}
