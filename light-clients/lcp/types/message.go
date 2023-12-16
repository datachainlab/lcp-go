package types

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/big"
	"time"

	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	clienttypes "github.com/cosmos/ibc-go/v7/modules/core/02-client/types"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
)

const (
	LCPMessageVersion          = 1
	LCPMessageTypeUpdateClient = 1
	LCPMessageTypeState        = 2
)

const (
	LCPMessageContextTypeEmpty          = 0
	LCPMessageContextTypeTrustingPeriod = 1
)

var (
	commitmentProofABI, _ = abi.NewType("tuple", "struct CommitmentProof", []abi.ArgumentMarshaling{
		{Name: "message", Type: "bytes"},
		{Name: "signer", Type: "address"},
		{Name: "signature", Type: "bytes"},
	})

	headeredMessageABI, _ = abi.NewType("tuple", "struct HeaderedMessage", []abi.ArgumentMarshaling{
		{Name: "header", Type: "bytes32"},
		{Name: "message", Type: "bytes"},
	})

	updateClientMessageABI, _ = abi.NewType("tuple", "struct UpdateClientMessage", []abi.ArgumentMarshaling{
		{Name: "prev_height", Type: "tuple", Components: []abi.ArgumentMarshaling{
			{Name: "revision_number", Type: "uint64"},
			{Name: "revision_height", Type: "uint64"},
		}},
		{Name: "prev_state_id", Type: "bytes32"},
		{Name: "post_height", Type: "tuple", Components: []abi.ArgumentMarshaling{
			{Name: "revision_number", Type: "uint64"},
			{Name: "revision_height", Type: "uint64"},
		}},
		{Name: "post_state_id", Type: "bytes32"},
		{Name: "timestamp", Type: "uint128"},
		{Name: "context", Type: "bytes"},
		{Name: "emitted_states", Type: "tuple[]", Components: []abi.ArgumentMarshaling{
			{Name: "height", Type: "tuple", Components: []abi.ArgumentMarshaling{
				{Name: "revision_number", Type: "uint64"},
				{Name: "revision_height", Type: "uint64"},
			}},
			{Name: "state", Type: "bytes"},
		}},
	})

	headeredMessageContextABI, _ = abi.NewType("tuple", "struct HeaderedMessageContext", []abi.ArgumentMarshaling{
		{Name: "header", Type: "bytes32"},
		{Name: "context_bytes", Type: "bytes"},
	})

	trustingPeriodContextABI, _ = abi.NewType("tuple", "struct TrustingPeriodValidationContext", []abi.ArgumentMarshaling{
		{Name: "timestamps", Type: "bytes32"},
		{Name: "params", Type: "bytes32"},
	})

	verifyMembershipMessageABI, _ = abi.NewType("tuple", "struct VerifyMembershipMessage", []abi.ArgumentMarshaling{
		{Name: "prefix", Type: "bytes"},
		{Name: "path", Type: "bytes"},
		{Name: "value", Type: "bytes32"},
		{Name: "height", Type: "tuple", Components: []abi.ArgumentMarshaling{
			{Name: "revision_number", Type: "uint64"},
			{Name: "revision_height", Type: "uint64"},
		}},
		{Name: "state_id", Type: "bytes32"},
	})
)

type StateID [32]byte

func (id StateID) EqualBytes(bz []byte) bool {
	return bytes.Equal(id[:], bz)
}

type ELCUpdateClientMessage struct {
	PrevHeight    *clienttypes.Height
	PrevStateID   *StateID
	PostHeight    clienttypes.Height
	PostStateID   StateID
	Timestamp     *big.Int
	Context       ValidationContext
	EmittedStates []EmittedState
}

type EmittedState struct {
	Height clienttypes.Height
	State  codectypes.Any
}

// ValidationContext is the interface of validation context.
type ValidationContext interface {
	Validate(time.Time) error
}

// EmptyValidationContext is the validation context for a commitment that does not require any validation.
type EmptyValidationContext struct{}

var _ ValidationContext = EmptyValidationContext{}

func (EmptyValidationContext) Validate(time.Time) error {
	return nil
}

// TrustingPeriodValidationContext is the commitment context for a commitment that requires the current time to be within the trusting period.
type TrustingPeriodValidationContext struct {
	UntrustedHeaderTimestamp time.Time
	TrustedStateTimestamp    time.Time
	TrustingPeriod           big.Int
	ClockDrift               big.Int
}

func DecodeTrustingPeriodValidationContext(timestamps, params [32]byte) *TrustingPeriodValidationContext {
	// 0-15: untrusted_header_timestamp
	// 16-31: trusted_state_timestamp
	untrustedHeaderTimestamp := timestampNanosBytesToTime(timestamps[:16])
	trustedStateTimestamp := timestampNanosBytesToTime(timestamps[16:32])

	// 0-15: trusting_period
	// 16-31: clock_drift
	trustingPeriod := uint128BytesToBigInt(params[:16])
	clockDrift := uint128BytesToBigInt(params[16:32])

	return &TrustingPeriodValidationContext{
		UntrustedHeaderTimestamp: untrustedHeaderTimestamp,
		TrustedStateTimestamp:    trustedStateTimestamp,
		TrustingPeriod:           trustingPeriod,
		ClockDrift:               clockDrift,
	}
}

func uint128BytesToBigInt(bz []byte) big.Int {
	if len(bz) != 16 {
		panic("invalid length")
	}
	var durationNanos big.Int
	durationNanos.SetBytes(bz)
	return durationNanos
}

func timestampNanosBytesToTime(bz []byte) time.Time {
	if len(bz) != 16 {
		panic("invalid length")
	}
	var (
		timestampNanos big.Int
		secs           big.Int
		nanos          big.Int
	)

	timestampNanos.SetBytes(bz)
	secs.Div(&timestampNanos, big.NewInt(1e9))
	nanos.Mod(&timestampNanos, big.NewInt(1e9))
	return time.Unix(secs.Int64(), nanos.Int64())
}

var _ ValidationContext = TrustingPeriodValidationContext{}

func timeToBigInt(t time.Time) big.Int {
	var (
		secs  big.Int
		nanos big.Int
	)
	secs.SetInt64(t.Unix())
	secs.Mul(&secs, big.NewInt(1e9))
	nanos.SetInt64(int64(t.Nanosecond()))
	secs.Add(&secs, &nanos)
	return secs
}

func (c TrustingPeriodValidationContext) Validate(now time.Time) error {
	currentTimestamp := timeToBigInt(now)
	trustedStateTimestamp := timeToBigInt(c.TrustedStateTimestamp)
	untrustedHeaderTimestamp := timeToBigInt(c.UntrustedHeaderTimestamp)

	var (
		trustingPeriodEnd       big.Int
		driftedCurrentTimestamp big.Int
	)
	trustingPeriodEnd.Add(&trustedStateTimestamp, &c.TrustingPeriod)
	driftedCurrentTimestamp.Add(&currentTimestamp, &c.ClockDrift)

	// ensure current timestamp is within trusting period
	if currentTimestamp.Cmp(&trustingPeriodEnd) > 0 {
		return fmt.Errorf("current time is after trusting period end: trusting_period_end=%v current=%v trusted_state_timestamp=%v trusting_period=%v", trustingPeriodEnd, now, c.TrustedStateTimestamp, c.TrustingPeriod)
	}
	// ensure header's timestamp indicates past
	if untrustedHeaderTimestamp.Cmp(&driftedCurrentTimestamp) > 0 {
		return fmt.Errorf("untrusted header timestamp is after current time: untrusted_header_timestamp=%v current=%v clock_drift=%v", c.UntrustedHeaderTimestamp, driftedCurrentTimestamp, c.ClockDrift)
	}
	return nil
}

type ELCVerifyMembershipMessage struct {
	Prefix  []byte
	Path    []byte
	Value   [32]byte
	Height  clienttypes.Height
	StateID StateID
}

type CommitmentProof struct {
	Message   []byte
	Signer    common.Address
	Signature []byte
}

func (p CommitmentProof) GetMessage() (*HeaderedELCMessage, error) {
	return EthABIDecodeHeaderedMessage(p.Message)
}

type HeaderedELCMessage struct {
	Version uint16
	Type    uint16
	Message []byte
}

func (c HeaderedELCMessage) GetUpdateClientMessage() (*ELCUpdateClientMessage, error) {
	if c.Version != LCPMessageVersion {
		return nil, fmt.Errorf("unexpected commitment version: expected=%v actual=%v", LCPMessageVersion, c.Version)
	}
	if c.Type != LCPMessageTypeUpdateClient {
		return nil, fmt.Errorf("unexpected commitment type: expected=%v actual=%v", LCPMessageTypeUpdateClient, c.Type)
	}
	return EthABIDecodeUpdateClientMessage(c.Message)
}

func (c HeaderedELCMessage) GetVerifyMembershipMessage() (*ELCVerifyMembershipMessage, error) {
	if c.Version != LCPMessageVersion {
		return nil, fmt.Errorf("unexpected commitment version: expected=%v actual=%v", LCPMessageVersion, c.Version)
	}
	if c.Type != LCPMessageTypeState {
		return nil, fmt.Errorf("unexpected commitment type: expected=%v actual=%v", LCPMessageTypeState, c.Type)
	}
	return EthABIDecodeVerifyMembershipMessage(c.Message)
}

func EthABIEncodeCommitmentProof(p *CommitmentProof) ([]byte, error) {
	packer := abi.Arguments{
		{Type: commitmentProofABI},
	}
	return packer.Pack(p)
}

func EthABIDecodeCommitmentProof(bz []byte) (*CommitmentProof, error) {
	unpacker := abi.Arguments{
		{Type: commitmentProofABI},
	}
	v, err := unpacker.Unpack(bz)
	if err != nil {
		return nil, err
	}
	p := CommitmentProof(v[0].(struct {
		Message   []byte         `json:"message"`
		Signer    common.Address `json:"signer"`
		Signature []byte         `json:"signature"`
	}))
	return &p, nil
}

func EthABIDecodeHeaderedMessage(bz []byte) (*HeaderedELCMessage, error) {
	unpacker := abi.Arguments{
		{Type: headeredMessageABI},
	}
	v, err := unpacker.Unpack(bz)
	if err != nil {
		return nil, err
	}
	p := v[0].(struct {
		Header  [32]byte `json:"header"`
		Message []byte   `json:"message"`
	})
	// Header format:
	// MSB first
	// 0-1:  version
	// 2-3:  message type
	// 4-31: reserved
	version := binary.BigEndian.Uint16(p.Header[:2])
	messageType := binary.BigEndian.Uint16(p.Header[2:4])
	return &HeaderedELCMessage{
		Version: version,
		Type:    messageType,
		Message: p.Message,
	}, nil
}

func EthABIDecodeUpdateClientMessage(bz []byte) (*ELCUpdateClientMessage, error) {
	unpacker := abi.Arguments{
		{Type: updateClientMessageABI},
	}
	v, err := unpacker.Unpack(bz)
	if err != nil {
		return nil, err
	}
	p := v[0].(struct {
		PrevHeight struct {
			RevisionNumber uint64 `json:"revision_number"`
			RevisionHeight uint64 `json:"revision_height"`
		} `json:"prev_height"`
		PrevStateId [32]byte `json:"prev_state_id"`
		PostHeight  struct {
			RevisionNumber uint64 `json:"revision_number"`
			RevisionHeight uint64 `json:"revision_height"`
		} `json:"post_height"`
		PostStateId   [32]byte `json:"post_state_id"`
		Timestamp     *big.Int `json:"timestamp"`
		Context       []byte   `json:"context"`
		EmittedStates []struct {
			Height struct {
				RevisionNumber uint64 `json:"revision_number"`
				RevisionHeight uint64 `json:"revision_height"`
			} `json:"height"`
			State []byte `json:"state"`
		} `json:"emitted_states"`
	})
	cctx, err := EthABIDecodeValidationContext(p.Context)
	if err != nil {
		return nil, err
	}
	c := &ELCUpdateClientMessage{
		PostStateID: p.PostStateId,
		PostHeight:  clienttypes.Height{RevisionNumber: p.PostHeight.RevisionNumber, RevisionHeight: p.PostHeight.RevisionHeight},
		Timestamp:   p.Timestamp,
		Context:     cctx,
	}
	if p.PrevStateId != [32]byte{} {
		prev := StateID(p.PrevStateId)
		c.PrevStateID = &prev
	}
	if p.PrevHeight.RevisionNumber != 0 || p.PrevHeight.RevisionHeight != 0 {
		c.PrevHeight = &clienttypes.Height{RevisionNumber: p.PrevHeight.RevisionNumber, RevisionHeight: p.PrevHeight.RevisionHeight}
	}
	for _, emitted := range p.EmittedStates {
		var anyState codectypes.Any
		if err := anyState.Unmarshal(emitted.State); err != nil {
			return nil, err
		}
		c.EmittedStates = append(c.EmittedStates, EmittedState{
			Height: clienttypes.Height{RevisionNumber: emitted.Height.RevisionNumber, RevisionHeight: emitted.Height.RevisionHeight},
			State:  anyState,
		})
	}
	return c, nil
}

func EthABIDecodeValidationContext(bz []byte) (ValidationContext, error) {
	unpacker := abi.Arguments{
		{Type: headeredMessageContextABI},
	}
	v, err := unpacker.Unpack(bz)
	if err != nil {
		return nil, err
	}
	p := v[0].(struct {
		Header       [32]byte `json:"header"`
		ContextBytes []byte   `json:"context_bytes"`
	})
	// Header format:
	// MSB first
	// 0-1:  type
	// 2-31: reserved
	contextType := binary.BigEndian.Uint16(p.Header[:2])
	switch contextType {
	case LCPMessageContextTypeEmpty:
		if len(p.ContextBytes) != 0 {
			return nil, fmt.Errorf("unexpected context bytes for empty commitment context: %X", p.ContextBytes)
		}
		return &EmptyValidationContext{}, nil
	case LCPMessageContextTypeTrustingPeriod:
		return EthABIDecodeTrustingPeriodValidationContext(p.ContextBytes)
	default:
		return nil, fmt.Errorf("unexpected commitment context type: %v", contextType)
	}
}

func EthABIDecodeTrustingPeriodValidationContext(bz []byte) (*TrustingPeriodValidationContext, error) {
	if len(bz) != 64 {
		return nil, fmt.Errorf("unexpected length of trusting period commitment context: %d", len(bz))
	}
	unpacker := abi.Arguments{
		{Type: trustingPeriodContextABI},
	}
	v, err := unpacker.Unpack(bz)
	if err != nil {
		return nil, err
	}
	p := v[0].(struct {
		Timestamps [32]byte `json:"timestamps"`
		Params     [32]byte `json:"params"`
	})
	return DecodeTrustingPeriodValidationContext(p.Timestamps, p.Params), nil
}

func EthABIDecodeVerifyMembershipMessage(bz []byte) (*ELCVerifyMembershipMessage, error) {
	unpacker := abi.Arguments{
		{Type: verifyMembershipMessageABI},
	}
	v, err := unpacker.Unpack(bz)
	if err != nil {
		return nil, err
	}
	p := v[0].(struct {
		Prefix []byte   `json:"prefix"`
		Path   []byte   `json:"path"`
		Value  [32]byte `json:"value"`
		Height struct {
			RevisionNumber uint64 `json:"revision_number"`
			RevisionHeight uint64 `json:"revision_height"`
		} `json:"height"`
		StateId [32]byte `json:"state_id"`
	})
	return &ELCVerifyMembershipMessage{
		Prefix:  p.Prefix,
		Path:    p.Path,
		Value:   p.Value,
		Height:  clienttypes.Height{RevisionNumber: p.Height.RevisionNumber, RevisionHeight: p.Height.RevisionHeight},
		StateID: StateID(p.StateId),
	}, nil
}
