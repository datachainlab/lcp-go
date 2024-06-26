package types

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
	"time"

	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	clienttypes "github.com/cosmos/ibc-go/v8/modules/core/02-client/types"
	"github.com/ethereum/go-ethereum/accounts/abi"
)

const (
	LCPMessageVersion          = 1
	LCPMessageTypeUpdateState  = 1
	LCPMessageTypeState        = 2
	LCPMessageTypeMisbehaviour = 3
)

const (
	LCPMessageContextTypeEmpty          = 0
	LCPMessageContextTypeTrustingPeriod = 1
)

var (
	commitmentProofsABI, _ = abi.NewType("tuple", "struct CommitmentProofs", []abi.ArgumentMarshaling{
		{Name: "message", Type: "bytes"},
		{Name: "signatures", Type: "bytes[]"},
	})

	headeredMessageABI, _ = abi.NewType("tuple", "struct HeaderedMessage", []abi.ArgumentMarshaling{
		{Name: "header", Type: "bytes32"},
		{Name: "message", Type: "bytes"},
	})

	updateStateProxyMessageABI, _ = abi.NewType("tuple", "struct UpdateStateProxyMessage", []abi.ArgumentMarshaling{
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

	misbehaviourProxyMessageABI, _ = abi.NewType("tuple", "struct MisbehaviourProxyMessage", []abi.ArgumentMarshaling{
		{Name: "prev_states", Type: "tuple[]", Components: []abi.ArgumentMarshaling{
			{Name: "height", Type: "tuple", Components: []abi.ArgumentMarshaling{
				{Name: "revision_number", Type: "uint64"},
				{Name: "revision_height", Type: "uint64"},
			}},
			{Name: "state_id", Type: "bytes32"},
		}},
		{Name: "context", Type: "bytes"},
		{Name: "client_message", Type: "bytes"},
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

func (id StateID) String() string {
	return fmt.Sprintf("0x%x", id[:])
}

func (id StateID) EqualBytes(bz []byte) bool {
	return bytes.Equal(id[:], bz)
}

func (id StateID) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf("\"%s\"", id.String())), nil
}

type UpdateStateProxyMessage struct {
	PrevHeight    *clienttypes.Height `json:"prev_height"`
	PrevStateID   *StateID            `json:"prev_state_id"`
	PostHeight    clienttypes.Height  `json:"post_height"`
	PostStateID   StateID             `json:"post_state_id"`
	Timestamp     *big.Int            `json:"timestamp"`
	Context       ValidationContext   `json:"context"`
	EmittedStates []EmittedState      `json:"emitted_states"`
}

type EmittedState struct {
	Height clienttypes.Height
	State  codectypes.Any
}

func (es EmittedState) MarshalJSON() ([]byte, error) {
	var es2 struct {
		Height clienttypes.Height `json:"height"`
		State  struct {
			TypeUrl string `json:"type_url"`
			Value   []byte `json:"value"`
		} `json:"state"`
	}
	es2.Height = es.Height
	es2.State.TypeUrl = es.State.TypeUrl
	es2.State.Value = es.State.Value
	return json.Marshal(es2)
}

type MisbehaviourProxyMessage struct {
	PrevStates []struct {
		Height  clienttypes.Height
		StateID StateID
	}
	Context       ValidationContext
	ClientMessage []byte
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
	UntrustedHeaderTimestamp time.Time `json:"untrusted_header_timestamp"`
	TrustedStateTimestamp    time.Time `json:"trusted_state_timestamp"`
	TrustingPeriod           big.Int   `json:"trusting_period"`
	ClockDrift               big.Int   `json:"clock_drift"`
}

func (c TrustingPeriodValidationContext) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		UntrustedHeaderTimestamp *big.Int `json:"untrusted_header_timestamp"`
		TrustedStateTimestamp    *big.Int `json:"trusted_state_timestamp"`
		TrustingPeriod           *big.Int `json:"trusting_period"`
		ClockDrift               *big.Int `json:"clock_drift"`
	}{
		UntrustedHeaderTimestamp: big.NewInt(c.UntrustedHeaderTimestamp.UnixNano()),
		TrustedStateTimestamp:    big.NewInt(c.TrustedStateTimestamp.UnixNano()),
		TrustingPeriod:           &c.TrustingPeriod,
		ClockDrift:               &c.ClockDrift,
	})
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

type CommitmentProofs struct {
	Message    []byte
	Signatures [][]byte
}

func (p CommitmentProofs) GetMessage() (*HeaderedProxyMessage, error) {
	return EthABIDecodeHeaderedProxyMessage(p.Message)
}

type HeaderedProxyMessage struct {
	Version uint16
	Type    uint16
	Message []byte
}

func (c HeaderedProxyMessage) GetUpdateStateProxyMessage() (*UpdateStateProxyMessage, error) {
	if c.Version != LCPMessageVersion {
		return nil, fmt.Errorf("unexpected commitment version: expected=%v actual=%v", LCPMessageVersion, c.Version)
	}
	if c.Type != LCPMessageTypeUpdateState {
		return nil, fmt.Errorf("unexpected commitment type: expected=%v actual=%v", LCPMessageTypeUpdateState, c.Type)
	}
	return EthABIDecodeUpdateStateProxyMessage(c.Message)
}

func (c HeaderedProxyMessage) GetMisbehaviourProxyMessage() (*MisbehaviourProxyMessage, error) {
	if c.Version != LCPMessageVersion {
		return nil, fmt.Errorf("unexpected commitment version: expected=%v actual=%v", LCPMessageVersion, c.Version)
	}
	if c.Type != LCPMessageTypeMisbehaviour {
		return nil, fmt.Errorf("unexpected commitment type: expected=%v actual=%v", LCPMessageTypeMisbehaviour, c.Type)
	}
	return EthABIDecodeMisbehaviourProxyMessage(c.Message)
}

func (c HeaderedProxyMessage) GetVerifyMembershipProxyMessage() (*ELCVerifyMembershipMessage, error) {
	if c.Version != LCPMessageVersion {
		return nil, fmt.Errorf("unexpected commitment version: expected=%v actual=%v", LCPMessageVersion, c.Version)
	}
	if c.Type != LCPMessageTypeState {
		return nil, fmt.Errorf("unexpected commitment type: expected=%v actual=%v", LCPMessageTypeState, c.Type)
	}
	return EthABIDecodeVerifyMembershipProxyMessage(c.Message)
}

func EthABIEncodeCommitmentProofs(p *CommitmentProofs) ([]byte, error) {
	packer := abi.Arguments{
		{Type: commitmentProofsABI},
	}
	return packer.Pack(p)
}

func EthABIDecodeCommitmentProofs(bz []byte) (*CommitmentProofs, error) {
	unpacker := abi.Arguments{
		{Type: commitmentProofsABI},
	}
	v, err := unpacker.Unpack(bz)
	if err != nil {
		return nil, fmt.Errorf("failed to unpack commitment proof: bz=%x %w", bz, err)
	}
	p := CommitmentProofs(v[0].(struct {
		Message    []byte   `json:"message"`
		Signatures [][]byte `json:"signatures"`
	}))
	return &p, nil
}

func EthABIDecodeHeaderedProxyMessage(bz []byte) (*HeaderedProxyMessage, error) {
	unpacker := abi.Arguments{
		{Type: headeredMessageABI},
	}
	v, err := unpacker.Unpack(bz)
	if err != nil {
		return nil, fmt.Errorf("failed to unpack headered message: bz=%x %w", bz, err)
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
	return &HeaderedProxyMessage{
		Version: version,
		Type:    messageType,
		Message: p.Message,
	}, nil
}

func EthABIDecodeUpdateStateProxyMessage(bz []byte) (*UpdateStateProxyMessage, error) {
	unpacker := abi.Arguments{
		{Type: updateStateProxyMessageABI},
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
	c := &UpdateStateProxyMessage{
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

func EthABIDecodeMisbehaviourProxyMessage(bz []byte) (*MisbehaviourProxyMessage, error) {
	unpacker := abi.Arguments{
		{Type: misbehaviourProxyMessageABI},
	}
	v, err := unpacker.Unpack(bz)
	if err != nil {
		return nil, fmt.Errorf("failed to unpack misbehaviourProxyMessage: bz=%x %w", bz, err)
	}
	p := v[0].(struct {
		PrevStates []struct {
			Height struct {
				RevisionNumber uint64 `json:"revision_number"`
				RevisionHeight uint64 `json:"revision_height"`
			} `json:"height"`
			StateId [32]byte `json:"state_id"`
		} `json:"prev_states"`
		Context       []byte `json:"context"`
		ClientMessage []byte `json:"client_message"`
	})
	cctx, err := EthABIDecodeValidationContext(p.Context)
	if err != nil {
		return nil, fmt.Errorf("failed to decode validation context: bz=%x %w", p.Context, err)
	}
	var prevStates []struct {
		Height  clienttypes.Height
		StateID StateID
	}
	for _, prev := range p.PrevStates {
		prevStates = append(prevStates, struct {
			Height  clienttypes.Height
			StateID StateID
		}{
			Height:  clienttypes.Height{RevisionNumber: prev.Height.RevisionNumber, RevisionHeight: prev.Height.RevisionHeight},
			StateID: prev.StateId,
		})
	}
	return &MisbehaviourProxyMessage{
		PrevStates:    prevStates,
		Context:       cctx,
		ClientMessage: p.ClientMessage,
	}, nil
}

func EthABIDecodeValidationContext(bz []byte) (ValidationContext, error) {
	unpacker := abi.Arguments{
		{Type: headeredMessageContextABI},
	}
	v, err := unpacker.Unpack(bz)
	if err != nil {
		return nil, fmt.Errorf("failed to unpack headered message context: bz=%x %w", bz, err)
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
		return nil, fmt.Errorf("unexpected length of trusting period commitment context: bz=%x", bz)
	}
	unpacker := abi.Arguments{
		{Type: trustingPeriodContextABI},
	}
	v, err := unpacker.Unpack(bz)
	if err != nil {
		return nil, fmt.Errorf("failed to unpack trusting period context: bz=%x %w", bz, err)
	}
	p := v[0].(struct {
		Timestamps [32]byte `json:"timestamps"`
		Params     [32]byte `json:"params"`
	})
	return DecodeTrustingPeriodValidationContext(p.Timestamps, p.Params), nil
}

func EthABIDecodeVerifyMembershipProxyMessage(bz []byte) (*ELCVerifyMembershipMessage, error) {
	unpacker := abi.Arguments{
		{Type: verifyMembershipMessageABI},
	}
	v, err := unpacker.Unpack(bz)
	if err != nil {
		return nil, fmt.Errorf("failed to unpack verify membership message: bz=%x %w", bz, err)
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
