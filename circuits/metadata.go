package circuits

const (
	// KYCBySignaturePublicSignalsSchema is schema to parse json data for additional information
	KYCBySignaturePublicSignalsSchema string = `{"user_identifier":0,"challenge":1,"countryClaimIssuerId":2,"countryClaimIssuerBBJIdenState":3,"countryBlacklist_1":4,"countryBlacklist_2":5,"countryBlacklist_3":6,"countryBlacklist_4":7,"countryBlacklist_5":8,"countryBlacklist_6":9,"countryBlacklist_7":10,"countryBlacklist_8":11,"countryBlacklist_9":12,"countryBlacklist_10":13,"countryBlacklist_11":14,"countryBlacklist_12":15,"countryBlacklist_13":16,"countryBlacklist_14":17,"countryBlacklist_15":18,"countryBlacklist_16":19,"birthdayClaimIssuerId":20,"birthdayClaimIssuerBBJIdenState":21,"currentYear":22,"currentMonth":23,"currentDay":24,"minAge":25}`

	// AuthenticationPublicSignalsSchema is schema to parse json data for additional information in auth circuit
	AuthenticationPublicSignalsSchema string = `{"challenge":0,"user_state":1,"user_identifier":2}`
)
