package state_test

import (
	"context"
	"math/big"
	"testing"

	core "github.com/iden3/go-iden3-core"

	"github.com/golang/mock/gomock"
	"github.com/iden3/go-iden3-auth/state"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"

	mock "github.com/iden3/go-iden3-auth/state/mock"
)

var (
	userID, _           = new(big.Int).SetString("24046132560195495514376446225096639477630837244209093211332602837583401473", 10)
	userGenesisState, _ = new(big.Int).SetString("7521024223205616003431860562270429547098131848980857190502964780628723574810", 10)
	userFirstState, _   = new(big.Int).SetString("6017654403209798611575982337826892532952335378376369712724079246845524041042", 10)
	userSecondState, _  = new(big.Int).SetString("13855704302023058120516733700521568675871224145197005519251383340112309153100", 10)
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
			name: "verify genesis state for user",
			contractResponse: func(m *mock.MockStateGetter) {
				res := state.StateInfo{
					State: big.NewInt(0),
				}
				m.EXPECT().GetStateInfoById(gomock.Any(), gomock.Any()).Return(res, nil)
			},
			userID:    userID,
			userState: userGenesisState,
			expected: &state.ResolvedState{
				State:               userGenesisState.String(),
				Genesis:             true,
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
			name: "state is not genesis and not registered in the smart contract",
			contractResponse: func(m *mock.MockStateGetter) {
				contractResponse := state.StateInfo{
					State: big.NewInt(0),
				}
				m.EXPECT().GetStateInfoById(gomock.Any(), gomock.Any()).Return(contractResponse, nil)
			},
			userID:        userID,
			userState:     userFirstState,
			expectedError: "state is not genesis and not registered in the smart contract",
		},
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

func TestResolveGlobalRoot_Success(t *testing.T) {
	tests := []struct {
		name             string
		contractResponse func(m *mock.MockGISTGetter)
		userID           *big.Int
		userState        *big.Int
		expected         *state.ResolvedState
	}{
		{
			name: "Last state has not been replaced",
			contractResponse: func(m *mock.MockGISTGetter) {
				ri := state.RootInfo{
					Root:               userFirstState,
					CreatedAtTimestamp: big.NewInt(1),
					ReplacedByRoot:     big.NewInt(0),
				}
				m.EXPECT().GetGISTRootInfo(gomock.Any(), gomock.Any()).Return(ri, nil)
			},
			userState: userFirstState,
			expected: &state.ResolvedState{
				State:               userFirstState.String(),
				Latest:              true,
				TransitionTimestamp: 0,
			},
		},
		{
			name: "Last state has been replaced",
			contractResponse: func(m *mock.MockGISTGetter) {
				ri := state.RootInfo{
					Root:                userFirstState,
					CreatedAtTimestamp:  big.NewInt(3),
					ReplacedByRoot:      big.NewInt(2),
					ReplacedAtTimestamp: big.NewInt(1),
				}
				m.EXPECT().GetGISTRootInfo(gomock.Any(), gomock.Any()).Return(ri, nil)
			},
			userState: userFirstState,
			expected: &state.ResolvedState{
				State:               userFirstState.String(),
				Latest:              false,
				TransitionTimestamp: 1,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			m := mock.NewMockGISTGetter(ctrl)
			tt.contractResponse(m)

			resState, err := state.ResolveGlobalRoot(context.Background(), m, tt.userState)
			require.NoError(t, err)
			require.Equal(t, tt.expected, resState)

			ctrl.Finish()
		})
	}
}

func TestResolveGlobalRoot_Error(t *testing.T) {
	tests := []struct {
		name             string
		contractResponse func(m *mock.MockGISTGetter)
		userID           *big.Int
		userState        *big.Int
		expectedError    string
	}{
		{
			name: "Contract call return an error",
			contractResponse: func(m *mock.MockGISTGetter) {
				err := errors.New("contract call error")
				m.EXPECT().GetGISTRootInfo(gomock.Any(), gomock.Any()).Return(state.RootInfo{}, err)
			},
			userState:     userFirstState,
			expectedError: "contract call error",
		},
		{
			name: "State has not been wrote to contract",
			contractResponse: func(m *mock.MockGISTGetter) {
				ri := state.RootInfo{
					CreatedAtTimestamp: big.NewInt(0),
				}
				m.EXPECT().GetGISTRootInfo(gomock.Any(), gomock.Any()).Return(ri, nil)
			},
			userState:     userFirstState,
			expectedError: "gist state not registered in the smart contract",
		},
		{
			name: "State has been wrote for another users",
			contractResponse: func(m *mock.MockGISTGetter) {
				ri := state.RootInfo{
					Root:               userSecondState,
					CreatedAtTimestamp: big.NewInt(3),
				}
				m.EXPECT().GetGISTRootInfo(gomock.Any(), gomock.Any()).Return(ri, nil)
			},
			userState:     userFirstState,
			expectedError: "gist info contains invalid state",
		},
		{
			name: "State was replaced, but replaced time is unknown",
			contractResponse: func(m *mock.MockGISTGetter) {
				ri := state.RootInfo{
					Root:                userFirstState,
					CreatedAtTimestamp:  big.NewInt(3),
					ReplacedByRoot:      userSecondState,
					ReplacedAtTimestamp: big.NewInt(0),
				}
				m.EXPECT().GetGISTRootInfo(gomock.Any(), gomock.Any()).Return(ri, nil)
			},
			userState:     userFirstState,
			expectedError: "state was replaced, but replaced time unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			m := mock.NewMockGISTGetter(ctrl)
			tt.contractResponse(m)

			resState, err := state.ResolveGlobalRoot(context.Background(), m, tt.userState)
			require.Nil(t, resState)
			require.EqualError(t, err, tt.expectedError)

			ctrl.Finish()
		})
	}
}

func TestCheckGenesisStateID(t *testing.T) {
	userDID, err := core.ParseDID("did:iden3:polygon:mumbai:x6suHR8HkEYczV9yVeAKKiXCZAd25P8WS6QvNhszk")
	require.NoError(t, err)
	genesisID, ok := big.NewInt(0).SetString("7521024223205616003431860562270429547098131848980857190502964780628723574810", 10)
	require.True(t, ok)

	isGenesis, err := state.CheckGenesisStateID(userDID.ID.BigInt(), genesisID)
	require.NoError(t, err)
	require.True(t, isGenesis)

	notGenesisState, ok := big.NewInt(0).SetString("6017654403209798611575982337826892532952335378376369712724079246845524041042", 10)
	require.True(t, ok)

	isGenesis, err = state.CheckGenesisStateID(userDID.ID.BigInt(), notGenesisState)
	require.NoError(t, err)
	require.False(t, isGenesis)
}
