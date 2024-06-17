package types

import (
	"encoding/binary"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
)

const (
	QuoteOK                                = "OK"
	QuoteSignatureInvalid                  = "SIGNATURE_INVALID"
	QuoteGroupRevoked                      = "GROUP_REVOKED"
	QuoteSignatureRevoked                  = "SIGNATURE_REVOKED"
	QuoteKeyRevoked                        = "KEY_REVOKED"
	QuoteSigRLVersionMismatch              = "SIGRL_VERSION_MISMATCH"
	QuoteGroupOutOfDate                    = "GROUP_OUT_OF_DATE"
	QuoteConfigurationNeeded               = "CONFIGURATION_NEEDED"
	QuoteSwHardeningNeeded                 = "SW_HARDENING_NEEDED"
	QuoteConfigurationAndSwHardeningNeeded = "CONFIGURATION_AND_SW_HARDENING_NEEDED"

	ChainTypeCosmos uint16 = 2
)

var (
	RegisterEnclaveKeyTypes = apitypes.Types{
		"EIP712Domain": []apitypes.Type{
			{Name: "name", Type: "string"},
			{Name: "version", Type: "string"},
			{Name: "chainId", Type: "uint256"},
			{Name: "verifyingContract", Type: "address"},
			{Name: "salt", Type: "bytes32"},
		},
		"RegisterEnclaveKey": []apitypes.Type{
			{Name: "avr", Type: "string"},
		},
	}

	UpdateOperatorsTypes = apitypes.Types{
		"EIP712Domain": []apitypes.Type{
			{Name: "name", Type: "string"},
			{Name: "version", Type: "string"},
			{Name: "chainId", Type: "uint256"},
			{Name: "verifyingContract", Type: "address"},
			{Name: "salt", Type: "bytes32"},
		},
		"UpdateOperators": []apitypes.Type{
			{Name: "clientId", Type: "string"},
			{Name: "nonce", Type: "uint64"},
			{Name: "newOperators", Type: "address[]"},
			{Name: "thresholdNumerator", Type: "uint64"},
			{Name: "thresholdDenominator", Type: "uint64"},
		},
	}
)

func ComputeChainSalt(chainID string, prefix []byte) common.Hash {
	msg := make([]byte, 2)
	binary.BigEndian.PutUint16(msg, ChainTypeCosmos)
	// TODO abi encode?
	msg = append(msg, []byte(chainID)...)
	msg = append(msg, prefix...)
	return crypto.Keccak256Hash(msg)
}

func LCPClientDomain(chainId int64, verifyingContract common.Address, salt common.Hash) apitypes.TypedDataDomain {
	return apitypes.TypedDataDomain{
		Name:              "LCPClient",
		Version:           "1",
		ChainId:           math.NewHexOrDecimal256(chainId),
		VerifyingContract: verifyingContract.Hex(),
		Salt:              salt.Hex(),
	}
}

func GetRegisterEnclaveKeyTypedData(salt common.Hash, avr string) apitypes.TypedData {
	return apitypes.TypedData{
		PrimaryType: "RegisterEnclaveKey",
		Types:       RegisterEnclaveKeyTypes,
		Domain:      LCPClientDomain(0, common.Address{}, salt),
		Message: apitypes.TypedDataMessage{
			"avr": avr,
		},
	}
}

func GetUpdateOperatorsTypedData(
	chainId int64,
	verifyingContract common.Address,
	salt common.Hash,
	clientID string,
	nonce uint64,
	newOperators []common.Address,
	newOperatorThresholdNumerator uint64,
	newOperatorThresholdDenominator uint64,
) apitypes.TypedData {
	newOperatorsStr := make([]string, len(newOperators))
	for i, o := range newOperators {
		newOperatorsStr[i] = o.Hex()
	}
	return apitypes.TypedData{
		PrimaryType: "UpdateOperators",
		Types:       UpdateOperatorsTypes,
		Domain:      LCPClientDomain(chainId, verifyingContract, salt),
		Message: apitypes.TypedDataMessage{
			"clientId":             clientID,
			"nonce":                fmt.Sprint(nonce),
			"newOperators":         newOperatorsStr,
			"thresholdNumerator":   fmt.Sprint(newOperatorThresholdNumerator),
			"thresholdDenominator": fmt.Sprint(newOperatorThresholdDenominator),
		},
	}
}

func ComputeEIP712RegisterEnclaveKeyWithSalt(salt common.Hash, report string) ([]byte, error) {
	_, raw, err := apitypes.TypedDataAndHash(GetRegisterEnclaveKeyTypedData(salt, report))
	if err != nil {
		return nil, err
	}
	return []byte(raw), nil
}

func ComputeEIP712RegisterEnclaveKey(chainID string, prefix []byte, report string) ([]byte, error) {
	return ComputeEIP712RegisterEnclaveKeyWithSalt(ComputeChainSalt(chainID, prefix), report)
}

func ComputeEIP712RegisterEnclaveKeyHash(chainID string, prefix []byte, report string) (common.Hash, error) {
	bz, err := ComputeEIP712RegisterEnclaveKey(chainID, prefix, report)
	if err != nil {
		return common.Hash{}, err
	}
	return crypto.Keccak256Hash(bz), nil
}

func ComputeEIP712UpdateOperatorsCosmos(
	chainID string,
	prefix []byte,
	clientID string,
	nonce uint64,
	newOperators []common.Address,
	newOperatorThresholdNumerator uint64,
	newOperatorThresholdDenominator uint64,
) ([]byte, error) {
	return ComputeEIP712UpdateOperators(0, common.Address{}, ComputeChainSalt(chainID, prefix), clientID, nonce, newOperators, newOperatorThresholdNumerator, newOperatorThresholdDenominator)
}

func ComputeEIP712UpdateOperators(
	chainId int64,
	verifyingContract common.Address,
	salt common.Hash,
	clientID string,
	nonce uint64,
	newOperators []common.Address,
	newOperatorThresholdNumerator uint64,
	newOperatorThresholdDenominator uint64,
) ([]byte, error) {
	_, raw, err := apitypes.TypedDataAndHash(
		GetUpdateOperatorsTypedData(chainId, verifyingContract, salt, clientID, nonce, newOperators, newOperatorThresholdNumerator, newOperatorThresholdDenominator),
	)
	if err != nil {
		return nil, err
	}
	return []byte(raw), nil
}

func RecoverAddress(commitment [32]byte, signature []byte) (common.Address, error) {
	if l := len(signature); l != 65 {
		return common.Address{}, fmt.Errorf("invalid signature length: expected=%v actual=%v", 65, l)
	}
	pubKey, err := secp256k1.RecoverPubkey(commitment[:], signature)
	if err != nil {
		return common.Address{}, err
	}
	pub, err := crypto.UnmarshalPubkey(pubKey)
	if err != nil {
		return common.Address{}, err
	}
	return crypto.PubkeyToAddress(*pub), nil
}

func VerifySignature(signBytes []byte, signature []byte) (common.Address, error) {
	msg := crypto.Keccak256Hash(signBytes)
	return RecoverAddress(msg, signature)
}
