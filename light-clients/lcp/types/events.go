package types

const (
	EventTypeRegisterEnclaveKey       = "register_enclave_key"
	EventTypeZKDCAPRegisterEnclaveKey = "zkdcap_register_enclave_key"
	AttributeKeyEnclaveKey            = "enclave_key"
	AttributeKeyExpiredAt             = "expired_at"
	AttributeKeyOperator              = "operator"

	EventTypeUpdateOperators         = "update_operators"
	AttributeKeyNonce                = "nonce"
	AttributeKeyNewOperators         = "new_operators"
	AttributeKeyThresholdNumerator   = "threshold_numerator"
	AttributeKeyThresholdDenominator = "threshold_denominator"

	EventTypeZKDCAPUpdateCurrentTCBEvaluationDataNumber = "zkdcap_update_current_tcb_evaluation_data_number"
	EventTypeZKDCAPUpdateNextTCBEvaluationDataNumber    = "zkdcap_update_next_tcb_evaluation_data_number"
	AttributeKeyTCBEvaluationDataNumber                 = "tcb_evaluation_data_number"
)
