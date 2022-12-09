package state_test

import (
	"context"
	"github.com/iden3/go-iden3-auth/state"
	"math/big"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"

	mock "github.com/iden3/go-iden3-auth/state/mock"
)

var (
	userID, _           = new(big.Int).SetString("24321776247489977391892714204849454424732134960326243894281082684329361408", 10)
	userGenesisState, _ = new(big.Int).SetString("371135506535866236563870411357090963344408827476607986362864968105378316288", 10)
	userFirstState, _   = new(big.Int).SetString("16751774198505232045539489584666775489135471631443877047826295522719290880931", 10)
	userSecondState, _  = new(big.Int).SetString("909633444088274766079863628649681053783162883711355065358662365638704113570", 10)
)

func TestResolve_Success(t *testing.T) {
	tests := []struct {
		name             string
		contractResponse func(m *mock.MockStateGetter)
		userID           *big.Int
		userState        *big.Int
		expected         *state.ResolvedState
	}{
		{
			name:             "verify genesis state for usser",
			contractResponse: func(m *mock.MockStateGetter) {},
			userID:           userID,
			userState:        userGenesisState,
			expected: &state.ResolvedState{
				State:               userGenesisState.String(),
				Latest:              true,
				TransitionTimestamp: 0,
			},
		},
		{
			name: "local state is latest state",
			contractResponse: func(m *mock.MockStateGetter) {
				contractResponse := state.StateInfo{
					Id:    userID,
					State: userFirstState,
				}
				m.EXPECT().GetStateInfoById(gomock.Any(), gomock.Any()).Return(contractResponse, nil)
			},
			userID:    userID,
			userState: userFirstState,
			expected: &state.ResolvedState{
				State:               userFirstState.String(),
				Latest:              true,
				TransitionTimestamp: 0,
			},
		},
		{
			name: "latest state exists on blockchain",
			contractResponse: func(m *mock.MockStateGetter) {
				contractResponse := state.StateInfo{
					Id:                  userID,
					State:               userSecondState,
					ReplacedAtTimestamp: big.NewInt(1000),
				}
				m.EXPECT().GetStateInfoById(gomock.Any(), gomock.Any()).Return(contractResponse, nil)
			},
			userID:    userID,
			userState: userFirstState,
			expected: &state.ResolvedState{
				State:               userFirstState.String(),
				Latest:              false,
				TransitionTimestamp: big.NewInt(1000).Int64(),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			m := mock.NewMockStateGetter(ctrl)
			tt.contractResponse(m)

			resState, err := state.Resolve(context.Background(), m, tt.userID, tt.userState)
			require.NoError(t, err)
			require.Equal(t, tt.expected, resState)

			ctrl.Finish()
		})
	}
}

func TestResolve_Error(t *testing.T) {
	tests := []struct {
		name             string
		contractResponse func(m *mock.MockStateGetter)
		userID           *big.Int
		userState        *big.Int
		expectedError    string
	}{
		{
			name: "state not found in contract",
			contractResponse: func(m *mock.MockStateGetter) {
				contractResponse := state.StateInfo{
					Id:    userID,
					State: big.NewInt(0),
				}
				m.EXPECT().GetStateInfoById(gomock.Any(), gomock.Any()).Return(contractResponse, nil)
			},
			userID:        userID,
			userState:     userFirstState,
			expectedError: "state is not genesis and not registered in the smart contract",
		},
		{
			name: "state info in contract contains invalid id",
			contractResponse: func(m *mock.MockStateGetter) {
				contractResponse := state.StateInfo{
					Id:    userFirstState, // use like invalid user ID.
					State: userSecondState,
				}
				m.EXPECT().GetStateInfoById(gomock.Any(), gomock.Any()).Return(contractResponse, nil)
			},
			userID:        userID,
			userState:     userFirstState,
			expectedError: "transition info contains invalid id",
		},
		{
			name: "unknown transition time from smart contract",
			contractResponse: func(m *mock.MockStateGetter) {
				contractResponse := state.StateInfo{
					Id:                  userID, // use like invalid user ID.
					State:               userSecondState,
					ReplacedAtTimestamp: big.NewInt(0),
				}
				m.EXPECT().GetStateInfoById(gomock.Any(), gomock.Any()).Return(contractResponse, nil)
			},
			userID:        userID,
			userState:     userFirstState,
			expectedError: "no information of transition for non-latest state",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			m := mock.NewMockStateGetter(ctrl)
			tt.contractResponse(m)

			resState, err := state.Resolve(context.Background(), m, tt.userID, tt.userState)
			require.Nil(t, resState)
			require.EqualError(t, err, tt.expectedError)

			ctrl.Finish()
		})
	}
}
