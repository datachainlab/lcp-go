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
	ChainTypeEVM    ChainType = 1
	ChainTypeCosmos ChainType = 2
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

	ZKDCAPRegisterEnclaveKeyTypes = apitypes.Types{
		"EIP712Domain": []apitypes.Type{
			{Name: "name", Type: "string"},
			{Name: "version", Type: "string"},
			{Name: "chainId", Type: "uint256"},
			{Name: "verifyingContract", Type: "address"},
			{Name: "salt", Type: "bytes32"},
		},
		"ZKDCAPRegisterEnclaveKey": []apitypes.Type{
			{Name: "zkDCAPVerifierInfo", Type: "bytes"},
			{Name: "commitHash", Type: "bytes32"},
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

type ChainType uint16

func (t ChainType) String() string {
	switch t {
	case ChainTypeEVM:
		return "EVM"
	case ChainTypeCosmos:
		return "Cosmos"
	default:
		return fmt.Sprintf("UnknownChainType(%d)", t.Uint16())
	}
}

func (t ChainType) Uint16() uint16 {
	return uint16(t)
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

func GetRegisterEnclaveKeyTypedData(avr string) apitypes.TypedData {
	return apitypes.TypedData{
		PrimaryType: "RegisterEnclaveKey",
		Types:       RegisterEnclaveKeyTypes,
		Domain:      LCPClientDomain(0, common.Address{}, common.Hash{}),
		Message: apitypes.TypedDataMessage{
			"avr": avr,
		},
	}
}

func GetZKDCAPRegisterEnclaveKeyTypedData(zkDCAPVerifierInfo [64]byte, commitHash [32]byte) apitypes.TypedData {
	return apitypes.TypedData{
		PrimaryType: "ZKDCAPRegisterEnclaveKey",
		Types:       ZKDCAPRegisterEnclaveKeyTypes,
		Domain:      LCPClientDomain(0, common.Address{}, common.Hash{}),
		Message: apitypes.TypedDataMessage{
			"zkDCAPVerifierInfo": zkDCAPVerifierInfo[:],
			"commitHash":         commitHash,
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

func ComputeEIP712RegisterEnclaveKey(report string) ([]byte, error) {
	_, raw, err := apitypes.TypedDataAndHash(GetRegisterEnclaveKeyTypedData(report))
	if err != nil {
		return nil, err
	}
	return []byte(raw), nil
}

func ComputeEIP712RegisterEnclaveKeyHash(report string) (common.Hash, error) {
	bz, err := ComputeEIP712RegisterEnclaveKey(report)
	if err != nil {
		return common.Hash{}, err
	}
	return crypto.Keccak256Hash(bz), nil
}

func ComputeEIP712ZKDCAPRegisterEnclaveKey(zkDCAPVerifierInfo [64]byte, commitHash [32]byte) ([]byte, error) {
	_, raw, err := apitypes.TypedDataAndHash(GetZKDCAPRegisterEnclaveKeyTypedData(zkDCAPVerifierInfo, commitHash))
	if err != nil {
		return nil, err
	}
	return []byte(raw), nil
}

func ComputeEIP712ZKDCAPRegisterEnclaveKeyHash(zkDCAPVerifierInfo [64]byte, commitHash [32]byte) (common.Hash, error) {
	bz, err := ComputeEIP712ZKDCAPRegisterEnclaveKey(zkDCAPVerifierInfo, commitHash)
	if err != nil {
		return common.Hash{}, err
	}
	return crypto.Keccak256Hash(bz), nil
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

// ----------- Cosmos Specific ------------

func ComputeCosmosChainSalt(chainID string, prefix []byte) common.Hash {
	// salt = Hash(| ChainType | Hash(ChainID) | Hash(Prefix) |)
	msg := make([]byte, 2)
	binary.BigEndian.PutUint16(msg, ChainTypeCosmos.Uint16())
	msg = append(msg, crypto.Keccak256Hash([]byte(chainID)).Bytes()...)
	msg = append(msg, crypto.Keccak256Hash(prefix).Bytes()...)
	return crypto.Keccak256Hash(msg)
}

func ComputeEIP712CosmosUpdateOperators(
	chainID string,
	prefix []byte,
	clientID string,
	nonce uint64,
	newOperators []common.Address,
	newOperatorThresholdNumerator uint64,
	newOperatorThresholdDenominator uint64,
) ([]byte, error) {
	return ComputeEIP712UpdateOperators(0, common.Address{}, ComputeCosmosChainSalt(chainID, prefix), clientID, nonce, newOperators, newOperatorThresholdNumerator, newOperatorThresholdDenominator)
}
