package auth

//
//import (
//	"context"
//	"encoding/json"
//	"github.com/iden3/go-schema-processor/verifiable"
//	"github.com/iden3/iden3comm"
//	"os"
//	"testing"
//
//	"github.com/iden3/go-circuits"
//	"github.com/stretchr/testify/assert"
//)
//
//func TestVerify(t *testing.T) {
//
//	var msg iden3comm.BasicMessage
//
//	msg.Type = auth.AuthorizationResponseMessageType
//	msgBody := auth.AuthorizationMessageResponseBody{}
//	zkpProof := auth.ZeroKnowledgeProof{
//		Type:      verifiable.ZeroKnowledgeProofType,
//		CircuitID: circuits.KycBySignaturesCircuitID,
//	}
//	zkpProof.ProofData = &verifiable.ProofData{
//		A: []string{"10441536817202584897377823144827964642356918402871315490038163167310235469676",
//			"3188873104904010906845899057040012497857652125001996465924027367142766788060",
//			"1"},
//		B: [][]string{{"10259767950868305572343651918722890484304440255374794205464892311274784569874",
//			"18113532891970083775734522192028652126404157383671158241782353379080674688210",
//		}, {
//			"20011188305329655231409527762393912898857036946232895893305954758470171745705",
//			"19212224402431449690017436050830610655559646158634403540885275057516508525272",
//		}, {
//			"1",
//			"0",
//		}},
//		C: []string{"17410066358263445906462947561105622363737416663317734129930901016400750644236",
//			"10889346016675221860511647187111664354773325795907973404602900127856769668544",
//			"1",
//		},
//	}
//	zkpProof.PubSignals = []string{"12345", "372902514040400364441393275265861152892555341750332828757240276565437644800", "19443506635601976434000063402326775248489014592264899338419890539515181882284", "840", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "372902514040400364441393275265861152892555341750332828757240276565437644800", "19443506635601976434000063402326775248489014592264899338419890539515181882284", "2021", "4", "25"}
//	msgBody.Scope = []auth.ZeroKnowledgeProof{}
//
//	marhalledScope, err := json.Marshal(msgBody)
//	assert.Nil(t, err)
//	msg.Body = marhalledScope
//	err = VerifyProofs(&msg)
//	assert.Nil(t, err)
//}
//
//func TestVerifyWrongMessage(t *testing.T) {
//
//	var message AuthorizationMessageRequest
//	message.Type = auth.AuthorizationRequestMessageType
//	message.Body = AuthorizationMessageRequestBody{}
//
//	zkpProofRequest := verifiable.ZeroKnowledgeProofRequest{
//		Type:      verifiable.ZeroKnowledgeProofType,
//		CircuitID: string(circuits.KycBySignaturesCircuitID),
//		Rules:     map[string]interface{}{},
//	}
//	message.Body.Scope = []verifiable.ZeroKnowledgeProofRequest{zkpProofRequest}
//
//	err := VerifyProofs(&message)
//
//	assert.NotNil(t, err)
//}
//
//func TestCreateAuthorizationRequest(t *testing.T) {
//
//	aud := "1125GJqgw6YEsKFwj63GY87MMxPL9kwDKxPUiwMLNZ"
//	zkpProofRequest := verifiable.ZeroKnowledgeProofRequest{
//		Type:      verifiable.ZeroKnowledgeProofType,
//		CircuitID: string(circuits.KycBySignaturesCircuitID),
//		Rules: map[string]interface{}{
//			"challenge":        12345678,
//			"countryBlacklist": []int{840},
//			"currentYear":      2021,
//			"currentMonth":     9,
//			"currentDay":       28,
//			"minAge":           18,
//			"audience":         aud,
//			"allowedIssuers": []string{
//				"115zTGHKvFeFLPu3vF9Wx2gBqnxGnzvTpmkHPM2LCe",
//				"115zTGHKvFeFLPu3vF9Wx2gBqnxGnzvTpmkHPM2LCe",
//			},
//		},
//	}
//
//	request := CreateAuthorizationRequest(10, aud, "https://test.com/callback")
//
//	request.WithZeroKnowledgeProofRequest(zkpProofRequest)
//
//	assert.Equal(t, 2, len(request.Body.Scope))
//
//}
//
//func TestVerifyMessageWithAuthProof(t *testing.T) {
//
//	var message iden3comm.BasicMessage
//	message.Type = auth.AuthorizationResponseMessageType
//	msgBody := auth.AuthorizationMessageResponseBody{}
//
//	zkpProof := auth.ZeroKnowledgeProof{
//		Type:      verifiable.ZeroKnowledgeProofType,
//		CircuitID: circuits.AuthCircuitID,
//	}
//
//	zkpProof.ProofData = &verifiable.ProofData{
//		A: []string{
//			"2370534291294441687575434871070063634049522739054135650290327914016792634144",
//			"18704664440065881255248484392571034267692380947539795837185393466696768539729",
//			"1",
//		},
//		B: [][]string{
//			{
//				"1593753415597360514506439944675236073038159742598884104707775208490282580641",
//				"15142074894866083200293799148931702287457526593114838706672766340147139402722",
//			},
//			{
//				"19117825221840408597122339519717065920080389822558089367138595722092823743944",
//				"2706264472260224656022451103720565978368804964791420659255319627595448027435",
//			},
//			{
//				"1",
//				"0",
//			}},
//		C: []string{
//			"156766304977057264803138092945401446963129379605822159500567538377014916135",
//			"10031227231200820171929683445407743402234929438478965985477678284516420821593",
//			"1",
//		},
//	}
//	zkpProof.PubSignals = []string{
//		"1",
//		"5816868615164565912277677884704888703982258184820398645933682814085602171910",
//		"286312392162647260160287083374160163061246635086990474403590223113720496128",
//	}
//	msgBody.Scope = []auth.ZeroKnowledgeProof{zkpProof}
//
//	marhsalledMessage, err := json.Marshal(msgBody)
//	assert.Nil(t, err)
//
//	message.Body = marhsalledMessage
//
//	err = VerifyProofs(&message)
//	assert.Nil(t, err)
//
//	token, err := ExtractMetadata(&message)
//	assert.Nil(t, err)
//	assert.Equal(t, "5816868615164565912277677884704888703982258184820398645933682814085602171910", token.State)
//	assert.Equal(t, "113Rq7d5grTGzqF7phKCRjxpC597eMa2USzm9rmpoj", token.ID)
//
//	state, err := token.VerifyState(context.Background(), os.Getenv("RPC_URL"), "0x035C4DBC897D203483D942696CE1dF5a9f933FcC")
//	assert.Nil(t, err)
//	assert.Equal(t, true, state.Latest)
//
//}
//
///*
//func TestVerifyMessageWithAuthAndAtomicProofMTP(t *testing.T) {
//
//	var message types.AuthorizationMessageResponse
//	message.Type = AuthorizationResponseMessageType
//	message.Data = types.AuthorizationMessageResponseData{}
//
//	zkpAuth := types.ZeroKnowledgeProof{
//		Type:      types.ZeroKnowledgeProofType,
//		CircuitID: circuits.AuthCircuitID,
//	}
//
//	zkpAuth.ProofData = &types.ProofData{
//		A: []string{
//			"2370534291294441687575434871070063634049522739054135650290327914016792634144",
//			"18704664440065881255248484392571034267692380947539795837185393466696768539729",
//			"1",
//		},
//		B: [][]string{
//			{
//				"1593753415597360514506439944675236073038159742598884104707775208490282580641",
//				"15142074894866083200293799148931702287457526593114838706672766340147139402722",
//			},
//			{
//				"19117825221840408597122339519717065920080389822558089367138595722092823743944",
//				"2706264472260224656022451103720565978368804964791420659255319627595448027435",
//			},
//			{
//				"1",
//				"0",
//			}},
//		C: []string{
//			"156766304977057264803138092945401446963129379605822159500567538377014916135",
//			"10031227231200820171929683445407743402234929438478965985477678284516420821593",
//			"1",
//		},
//	}
//	zkpAuth.PubSignals = []string{
//		"1",
//		"5816868615164565912277677884704888703982258184820398645933682814085602171910",
//		"286312392162647260160287083374160163061246635086990474403590223113720496128",
//	}
//	zkpAtomic := types.ZeroKnowledgeProof{
//		Type:      types.ZeroKnowledgeProofType,
//		CircuitID: circuits.AtomicQueryMTPCircuitID,
//	}
//
//	zkpAtomic.ProofData = &types.ProofData{
//		A: []string{
//			"6030766736698709207503235935723632085586029528521094738928233216811480909046",
//			"4437136509574400225154484002038044352118866895728605877220163266688442697592",
//			"1",
//		},
//		B: [][]string{
//			{
//				"15453350172140966014073430212249205778693880717093820193563857180042745981851",
//				"14488444741965254532105148685589475266981176437305146636275604446328498705645",
//			},
//			{
//				"13806971963548792566531398385681144495082522845543761509446816014383821923698",
//				"19957785137858923832827931038978551647136133568993960686008633889509690940365",
//			},
//			{
//				"1",
//				"0",
//			}},
//		C: []string{
//			"21292219848582385743964407300399360838478079150292968775627171001173922067285",
//			"75068403233603473513513911957593156375764622075671912015406661182104632457",
//			"1",
//		},
//	}
//	zkpAtomic.PubSignals = []string{
//		"286312392162647260160287083374160163061246635086990474403590223113720496128",
//		"5816868615164565912277677884704888703982258184820398645933682814085602171910",
//		"1",
//		"274380136414749538182079640726762994055",
//		"20606705619830543359176597576564222044873771515109680973150322899613614552596",
//		"296941560404583387587196218166209608454370683337298127000644446413747191808",
//		"2",
//		"10",
//		"0",
//		"0",
//		"0",
//		"0",
//		"0",
//		"0",
//		"0",
//		"0",
//		"0",
//		"0",
//		"0",
//		"0",
//		"0",
//		"0",
//		"0",
//		"0",
//		"1642074362",
//	}
//	message.Data.Scope = []interface{}{zkpAuth, zkpAtomic}
//
//	err := VerifyProofs(&message)
//	assert.Nil(t, err)
//
//	token, err := ExtractMetadata(&message)
//	assert.Nil(t, err)
//	assert.Equal(t, "5816868615164565912277677884704888703982258184820398645933682814085602171910", token.State)
//	assert.Equal(t, "113Rq7d5grTGzqF7phKCRjxpC597eMa2USzm9rmpoj", token.ID)
//	//
//	state, err := token.VerifyState(context.Background(), os.Getenv("RPC_URL"), "0x035C4DBC897D203483D942696CE1dF5a9f933FcC")
//	assert.Nil(t, err)
//	assert.Equal(t, true, state.Latest)
//
//}
//func TestVerifyMessageWithAuthAndAtomicProofSig(t *testing.T) {
//
//	var message types.AuthorizationMessageResponse
//	message.Type = AuthorizationResponseMessageType
//	message.Data = types.AuthorizationMessageResponseData{}
//
//	zkpAuth := types.ZeroKnowledgeProof{
//		Type:      types.ZeroKnowledgeProofType,
//		CircuitID: circuits.AuthCircuitID,
//	}
//
//	zkpAuth.ProofData = &types.ProofData{
//		A: []string{
//			"2370534291294441687575434871070063634049522739054135650290327914016792634144",
//			"18704664440065881255248484392571034267692380947539795837185393466696768539729",
//			"1",
//		},
//		B: [][]string{
//			{
//				"1593753415597360514506439944675236073038159742598884104707775208490282580641",
//				"15142074894866083200293799148931702287457526593114838706672766340147139402722",
//			},
//			{
//				"19117825221840408597122339519717065920080389822558089367138595722092823743944",
//				"2706264472260224656022451103720565978368804964791420659255319627595448027435",
//			},
//			{
//				"1",
//				"0",
//			}},
//		C: []string{
//			"156766304977057264803138092945401446963129379605822159500567538377014916135",
//			"10031227231200820171929683445407743402234929438478965985477678284516420821593",
//			"1",
//		},
//	}
//	zkpAuth.PubSignals = []string{
//		"1",
//		"5816868615164565912277677884704888703982258184820398645933682814085602171910",
//		"286312392162647260160287083374160163061246635086990474403590223113720496128",
//	}
//	zkpAtomic := types.ZeroKnowledgeProof{
//		Type:      types.ZeroKnowledgeProofType,
//		CircuitID: circuits.AtomicQuerySigCircuitID,
//	}
//
//	zkpAtomic.ProofData = &types.ProofData{
//		A: []string{
//			"21178773137304249408018096919215793146186660193600590200162998171616690680862",
//			"16723112137222954968898173855229909328853328041073537712042644179394618395718",
//			"1",
//		},
//		B: [][]string{
//			{
//				"8154027924267780522239744810441934681489939329198303707054340169107503503140",
//				"13896707211429361892074216485456946320669555884653797826533153207946250359049",
//			},
//			{
//				"8812219892284825088614656710055314118836154185354535911423155023728785526230",
//				"1137286278173265884575737920332918824261782651899335984176084421710066567443",
//			},
//			{
//				"1",
//				"0",
//			}},
//		C: []string{
//			"21449679392663656551219603482072298649562605845908654459293574785782180912646",
//			"3048812808090764561109652462842759548958106605480847082632940766239677991498",
//			"1",
//		},
//	}
//	zkpAtomic.PubSignals = []string{
//		"286312392162647260160287083374160163061246635086990474403590223113720496128",
//		"5816868615164565912277677884704888703982258184820398645933682814085602171910",
//		"1",
//		"274380136414749538182079640726762994055",
//		"296941560404583387587196218166209608454370683337298127000644446413747191808",
//		"13850938450891658391727543833954835315278162931905851620922327407976321180678",
//		"2",
//		"10",
//		"0",
//		"0",
//		"0",
//		"0",
//		"0",
//		"0",
//		"0",
//		"0",
//		"0",
//		"0",
//		"0",
//		"0",
//		"0",
//		"0",
//		"0",
//		"0",
//		"1642074362",
//	}
//	message.Data.Scope = []interface{}{zkpAuth, zkpAtomic}
//
//	err := VerifyProofs(&message)
//	assert.Nil(t, err)
//
//	token, err := ExtractMetadata(&message)
//	assert.Nil(t, err)
//	assert.Equal(t, "5816868615164565912277677884704888703982258184820398645933682814085602171910", token.State)
//	assert.Equal(t, "113Rq7d5grTGzqF7phKCRjxpC597eMa2USzm9rmpoj", token.ID)
//	//
//	state, err := token.VerifyState(context.Background(), os.Getenv("RPC_URL"), "0x035C4DBC897D203483D942696CE1dF5a9f933FcC")
//	assert.Nil(t, err)
//	assert.Equal(t, true, state.Latest)
//
//}
//*/
