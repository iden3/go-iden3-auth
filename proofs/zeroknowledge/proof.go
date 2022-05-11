package zeroknowledge

import (
	"github.com/iden3/go-circuits"
	"github.com/iden3/go-iden3-auth/proofs/zeroknowledge/handlers"
	types "github.com/iden3/go-iden3-auth/types"
)

var supportedCircuits = map[circuits.CircuitID]types.CircuitData{

	circuits.AuthCircuitID: {
		ID:          circuits.AuthCircuitID,
		Description: "circuit for verification of  basic authentication",
		Metadata:    `{"challenge":0,"userState":1,"userID":2}`,
	},
	circuits.AtomicQueryMTPCircuitID: {
		ID:          circuits.AtomicQueryMTPCircuitID,
		Description: "circuit for atomic query on standard iden3 credential",
		Metadata: `{"userID":0, "userState":1,"challenge":2,"issuerClaimIdenState":3, 
"issuerID":4,"timestamp":5,"claimSchema":6,"slotIndex":7, "operator":8, "value_0": 9, "value_1": 10, "value_2": 11, "value_3": 12, "value_4": 13, "value_5": 14, "value_6": 15, "value_7": 16, "value_8": 17, "value_9": 18, "value_10": 19, "value_11": 20, "value_12": 21, "value_13": 22, "value_14": 23, "value_15": 24, "value_16": 25, "value_17": 26, "value_18": 27, "value_19": 28, "value_20": 29, "value_21": 30, "value_22": 31, "value_23": 32, "value_24": 33, "value_25": 34, "value_26": 35, "value_27": 36, "value_28": 37, "value_29": 38, "value_30": 39, "value_31": 40, "value_32": 41, "value_33": 42, "value_34": 43, "value_35": 44, "value_36": 45, "value_37": 46, "value_38": 47, "value_39": 48, "value_40": 49, "value_41": 50, "value_42": 51, "value_43": 52, "value_44": 53, "value_45": 54, "value_46": 55, "value_47": 56, "value_48": 57, "value_49": 58, "value_50": 59, "value_51": 60, "value_52": 61, "value_53": 62, "value_54": 63, "value_55": 64, "value_56": 65, "value_57": 66, "value_58": 67, "value_59": 68, "value_60": 69, "value_61": 70, "value_62": 71, "value_63": 72}`,
	},
	circuits.AtomicQuerySigCircuitID: {
		ID:          circuits.AtomicQuerySigCircuitID,
		Description: "circuit for atomic query on standard iden3 credential",
		Metadata: `{"IssuerAuthState": 0, "userID": 1, "userState": 2, "challenge": 3, 
 "issuerID": 4,"issuerState":5,"issuerClaimNonRevState": 6, "timestamp": 7,  "claimSchema": 8, "slotIndex":9, "operator": 10, "value_0": 11, "value_1": 12, "value_2": 13, "value_3": 14, "value_4": 15, "value_5": 16, "value_6": 17, "value_7": 18, "value_8": 19, "value_9": 20, "value_10": 21, "value_11": 22, "value_12": 23, "value_13": 24, "value_14": 25, "value_15": 26, "value_16": 27, "value_17": 28, "value_18": 29, "value_19": 30, "value_20": 31, "value_21": 32, "value_22": 33, "value_23": 34, "value_24": 35, "value_25": 36, "value_26": 37, "value_27": 38, "value_28": 39, "value_29": 40, "value_30": 41, "value_31": 42, "value_32": 43, "value_33": 44, "value_34": 45, "value_35": 46, "value_36": 47, "value_37": 48, "value_38": 49, "value_39": 50, "value_40": 51, "value_41": 52, "value_42": 53, "value_43": 54, "value_44": 55, "value_45": 56, "value_46": 57, "value_47": 58, "value_48": 59, "value_49": 60, "value_50": 61, "value_51": 62, "value_52": 63, "value_53": 64, "value_54": 65, "value_55": 66, "value_56": 67, "value_57": 68, "value_58": 69, "value_59": 70, "value_60": 71, "value_61": 72, "value_62": 73, "value_63": 74}`,
	},
}

// VerifyProof performs groth16 verification
func VerifyProof(m *types.ZeroKnowledgeProof) (err error) {

	zkp := &handlers.ZeroKnowledgeProofHandler{}

	ch := &handlers.CircuitHandler{
		SupportedCircuits: supportedCircuits,
	}
	zkp.SetNext(ch)

	vh := &handlers.VerificationHandler{}
	ch.SetNext(vh)

	return zkp.Process(m)
}

// ExtractMetadata extracts proof metadata
func ExtractMetadata(m *types.ZeroKnowledgeProof) (err error) {

	zkp := &handlers.ZeroKnowledgeProofHandler{}

	ch := &handlers.CircuitHandler{
		SupportedCircuits: supportedCircuits,
	}

	mph := &handlers.MetadataProofHandler{}
	ch.SetNext(mph)
	zkp.SetNext(ch)

	err = zkp.Process(m)
	return err
}
