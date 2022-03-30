package verification

import (
	"context"
	"flag"
	"log"
	"math/big"
	"os"
	"testing"

	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/stretchr/testify/assert"
)

var integrationFlag bool

func init() {
	flag.BoolVar(&integrationFlag, "integration", false, "run integration tests")
}

var mockRPCURL = os.Getenv("RPC_URL")
var mockContractAddress = "0xE4F771f86B34BF7B323d9130c385117Ec39377c3" // before transition
var mockGenesisID, _ = new(big.Int).SetString("371135506535866236563870411357090963344408827476607986362864968105378316288", 10)
var mockGenesisState, _ = new(big.Int).SetString("16751774198505232045539489584666775489135471631443877047826295522719290880931", 10)

var mockIDForPublishedLatestState, _ = new(big.Int).SetString("259789390735913800425840589583206248151905278055521460389980943556380393472", 10) // "113VqmfwkGbKQJLfHuqFCAyLNwWThQL9pXzLVKwYuY"
var mockPublishedLatestState, _ = new(big.Int).SetString("14765322533580957814676911851067597009232239218105294460702004369607798613104", 10)    // "70e45c320615b74ff47ba7d908607d4ebf64ea5b69b91de21a989c955be0a420"

var mockContractAddressForTransitionTest = "0x456D5eD5dca5A4B46cDeF12ff0Fc9F0c60A29Afe" // before transition
var mockIDForTransitionTest, _ = new(big.Int).SetString("367594446074802395435725357511631230269128032558677653124422983977269133312", 10)

var mockGenesisFistStateForTransitionTest, _ = new(big.Int).SetString("15897377538691446922446254839699772977046010197592168446070901098705306666881", 10)
var mockGenesisSecondStateForTransitionTest, _ = new(big.Int).SetString("4731993948302075242049583490455206958215855607561993573829963977614219476117", 10)

func TestVerifyState(t *testing.T) {

	var c *ethclient.Client

	log.Println("!!!!!!!flag", integrationFlag)

	t.Run("", func(t *testing.T) {
		t.Helper()
		if integrationFlag {
			c, _ = ethclient.Dial(mockRPCURL)
		}
	})

	stateResult, err := VerifyState(context.Background(), c, mockContractAddress, mockGenesisID, mockGenesisState)
	assert.Nil(t, err)
	assert.Equal(t, true, stateResult.Latest)
}

//func TestVerifyInvalidRPC(t *testing.T) {
//
//	invalidURL := "test://invalidurl1234.com"
//	_, err := VerifyState(context.Background(), invalidURL, mockContractAddress, mockGenesisID, mockGenesisState)
//	assert.NotNil(t, err)
//	assert.Contains(t, err.Error(), errRPCClientCreationMessage)
//
//	invalidURL = "http://invalidurl1234.com"
//	_, err = VerifyState(context.Background(), invalidURL, mockContractAddress, mockGenesisID, mockGenesisState)
//
//	assert.NotNil(t, err)
//	assert.Contains(t, err.Error(), "no such host")
//
//}
//
//func TestVerifyGenesisState(t *testing.T) {
//
//	stateResult, err := VerifyState(context.Background(), mockRPCURL, mockContractAddress, mockGenesisID, mockGenesisState)
//	assert.Nil(t, err)
//	assert.Equal(t, true, stateResult.Latest)
//
//}
//
//func TestVerifyGenesisStateWrongID(t *testing.T) {
//
//	wrongID, _ := new(big.Int).SetString("26592849444054787445766572449338308165040390141345377877344569181291872256", 10)
//	_, err := VerifyState(context.Background(), mockRPCURL, mockContractAddress, wrongID, mockGenesisState)
//	assert.NotNil(t, err)
//	assert.Error(t, err, "ID from genesis state (11A2HgCZ1pUcY8HoNDMjNWEBQXZdUnL3YVnVCUvR5s) and provided (118cr7d17eL2sSYk5hrMBo9MKJrWGD5RrFgsqXupGE) don't match")
//
//}
//
//func TestVerifyPublishedLatestState(t *testing.T) {
//
//	stateResult, err := VerifyState(context.Background(), mockRPCURL, mockContractAddress, mockIDForPublishedLatestState, mockPublishedLatestState)
//	assert.Nil(t, err)
//	assert.Equal(t, true, stateResult.Latest)
//}
//
//func TestVerifyStateTransitionCheck(t *testing.T) {
//
//	// latest state - equal
//	stateResult1, err := VerifyState(context.Background(), mockRPCURL, mockContractAddressForTransitionTest, mockIDForTransitionTest, mockGenesisSecondStateForTransitionTest)
//	assert.Nil(t, err)
//	assert.Equal(t, true, stateResult1.Latest)
//
//	// latest state - not equal
//	stateResult2, err := VerifyState(context.Background(), mockRPCURL, mockContractAddressForTransitionTest, mockIDForTransitionTest, mockGenesisFistStateForTransitionTest)
//	assert.Nil(t, err)
//	assert.Equal(t, false, stateResult2.Latest)
//	assert.NotEqual(t, 0, stateResult2.TransitionTimestamp)
//
//}
