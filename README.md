# go-iden3-auth

> Library for authentication and authorization that is used in the communication protocol
>


`go get github.com/iden3/go-iden3-auth`

### General description:

The goal of iden3auth libraries is to handle authentication messages of communication protocol.

Currently, library implementation includes support of next message types

1. `https://iden3-communication.io/authorization-request/v1`
2. `https://iden3-communication.io/authorization-response/v1`

The library supports the creation of authorization requests with a possibility to request zero-knowledge proofs and signature proofs.

- Example of authorization request:

    ```json
    {
      "type": "https://iden3-communication.io/authorization-request/v1",
      "data": {
        "callbackUrl": "https://test.com",
        "audience": "1125GJqgw6YEsKFwj63GY87MMxPL9kwDKxPUiwMLNZ",
        "scope": [
          {
            "circuit_id": "kycBySignatures",
            "type": "zeroknowledge",
            "rules": {
              "challenge": "1234567"
            }
          }
        ]
      }
    }
    ```

    💡 <br />
    _type_ - represents protocol message kind <br />
    _scope_ is an array of all proof that are requested by verifier<br />
    _audience_ is a verifier identifier or url<br />
    _callbackUrl_  is an URL  where requested party should send a response message<br />


- Sample of authorization request creation

    ```go
    aud := "1125GJqgw6YEsKFwj63GY87MMxPL9kwDKxPUiwMLNZ" // verifier ID
    zkpProofRequest := types.ZeroKnowledgeProofRequest{ // prepared ZKP request for KYC circuit
    		Type:      types.ZeroKnowledgeProofType,
    		CircuitID: types.KycBySignaturesCircuitID,
    		Rules: map[string]interface{}{
    			"challenge":        12345678,
    			"countryBlacklist": []int{840},
    			"currentYear":      2021,
    			"currentMonth":     9,
    			"currentDay":       28,
    			"minAge":           18,
    			"audience":         aud,
    			"allowedIssuers": []string{
    				"115zTGHKvFeFLPu3vF9Wx2gBqnxGnzvTpmkHPM2LCe",
    				"115zTGHKvFeFLPu3vF9Wx2gBqnxGnzvTpmkHPM2LCe",
    			},
    		},
    	}
    
    	request := CreateAuthorizationRequest(aud, "https://test.com/callback") //creation
    	request.WithDefaultAuth(10) // ask for default authentication
    	request.WithZeroKnowledgeProofRequest(zkpProofRequest) // ask for specific proof
    ```


Also, it supports the verification of authorization-response.

- Example of authorization response:

    ```json
    {
      "type": "https://iden3-communication.io/authorization-response/v1",
      "data": {
        "scope": [
          {
            "type": "zeroknowledge",
            "circuit_id": "auth",
            "pub_signals": [
              "383481829333688262229762912714748186426235428103586432827469388069546950656",
              "12345"
            ],
            "proof_data": {
              "pi_a": [
                "14146277947056297753840642586002829867111675410988595047766001252156753371528",
                "14571022849315211248046007113544986624773029852663683182064313232057584750907",
                "1"
              ],
              "pi_b": [
                [
                  "16643510334478363316178974136322830670001098048711963846055396047727066595515",
                  "10398230582752448515583571758866992012509398625081722188208617704185602394573"
                ],
                [
                  "6754852150473185509183929580585027939167256175425095292505368999953776521762",
                  "4988338043999536569468301597030911639875135237017470300699903062776921637682"
                ],
                [
                  "1",
                  "0"
                ]
              ],
              "pi_c": [
                "17016608018243685488662035612576776697709541343999980909476169114486580874935",
                "1344455328868272682523157740509602348889110849570014394831093852006878298645",
                "1"
              ],
              "protocol": "groth16"
            }
          }
        ]
      }
    }
    ```

    💡 <br />
    *proof_data* is groth16 proof <br />
    *pub_signals*  are public inputs of proof that were used by prover <br />
    *circuit_id* is identifier of specific circuit that was used for proof <br />

   

- Sample of authorization response handling

    ```go
    message, err := packer.Unpack(msgBytes) // unpack raw message
    err = auth.Verify(message)  // call to library to verify zkp proofs
    if err != nil {
    		// do smth ...
    }
    token, err := auth.ExtractMetadata(message)
    if err != nil {
    		// do smth ...
    }
    stateInfo, err := auth.VerifyState(token,"< rpc url >", "< state contract address >")
    if err != nil {
    		// do smth ...
    }
    log.Infof("user identifier from token %s", token.Identifier) // we can get user id from proofs 
    log.Infof("auth challenge that was %s", token.Challenge) // we can get challenge from proofs 
    log.Infof("any other info from token %+v", token.Scope) // we can get any info according to circuit schemas
    log.Infof("state information latest: %t, transition time: %v", stateInfo.Latest, stateInfo.TransitionTimestamp) // we can get info about state

   ```


Auth library works with plain packer which doesn't support encoding or encryption but it can be implemented by introducing another packer.

- Packer interface

    ```go
    // Packer converts message to encrypted or encoded form
    type Packer interface {
    	// Pack a payload of type ContentType in an Iden3 compliant format using the sender identity
    	Pack(contentType string, payload types.Message) ([]byte, error)
    	// Unpack an envelope in Iden3 compliant format.
    	Unpack(envelope []byte) (*types.Message, error)
    }
    ```

- Sample of plain packer using

    ```go
    
    request := CreateAuthorizationRequest(aud, "https://test.com/callback") //creation
    request.WithDefaultAuth(challenge) // ask for default authentication
    
    msgBytes, err := packer.Pack("application/json", &request) // pack any message
    
    message, err := packer.Unpack(msgBytes) // unpack raw message
    
    ```


---

Auth verification procedure:

1. Zero-knowledge proof verification
2. Extraction of metadata: (auth and circuit-specific)
3. Verification of user identity states
4. Verification of claim non-revocation and issuers states

### Zero-knowledge proof verification

> Groth16 proof are supported now by auth library
>

Verification keys for circuits are known by the library itself. In the future, they can be resolved from circuits registries.

### Extraction of metadata

Each circuit has a schema of its public inputs that links the public signal name to its position in the resulted array.

This allows extracting user identifiers and challenges for authentication from proof.

Other signals are added to the user token ( scope field) as attributes of a specific circuit.

Circuit public signals schemas are known by this library or can be retrieved from some registry.

### Verification of user identity states

The blockchain verification algorithm is used

1. Gets state from the blockchain (address of id state contract and URL must be provided by the caller of the library):
  1. Empty state is returned - it means that identity state hasn’t been updated or updated state hasn’t been published. We need to compare id and state. If they are different it’s not a genesis state of identity then it’s not valid.
  2. The non-empty state is returned and equals to the state in provided proof which means that the user state is fresh enough and we work with the latest user state.
  3. The non-empty state is returned and it’s not equal to the state that the user has provided. Gets the transition time of the state. The verification party can make a decision if it can accept this state based on that time frame

2. Verification party can make a decision to accept or not provided state information
