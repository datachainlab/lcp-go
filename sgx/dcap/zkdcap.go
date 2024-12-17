package dcap

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/oasisprotocol/oasis-core/go/common/sgx"
	"github.com/oasisprotocol/oasis-core/go/common/sgx/pcs"
)

const (
	DCAPQuoteVerifierVersion = 0

	UnspecifiedZKVMType ZKVMType = 0
	Risc0ZKVMType       ZKVMType = 1
)

var (
	advisoryIdsABI, _ = abi.NewType("string[]", "", nil)
)

type ZKVMType uint8

func (t ZKVMType) String() string {
	switch t {
	case Risc0ZKVMType:
		return "Risc0"
	default:
		return fmt.Sprintf("UnknownZKVMType(%d)", t)
	}
}

type VerifiedOutput struct {
	Version            uint16
	QuoteVersion       uint16
	TeeType            uint32
	TcbStatus          TCBStatus
	Fmspc              [6]byte
	SGXIntelRootCAHash [32]byte
	Validity           ValidityIntersection
	QuoteBody          QuoteBody
	AdvisoryIds        []string
}

func (vo VerifiedOutput) ReportData() []byte {
	return vo.QuoteBody.ReportData()
}

func (vo VerifiedOutput) GetEnclaveIdentity() sgx.EnclaveIdentity {
	return vo.QuoteBody.AsEnclaveIdentity()
}

func (vo VerifiedOutput) IsDebug() (bool, error) {
	attrs, err := GetAttributesFromSgxReport(&vo.QuoteBody)
	if err != nil {
		return false, err
	}
	return attrs.Flags&sgx.AttributeDebug == 1, nil
}

func (vo VerifiedOutput) GetExpiredAt() time.Time {
	return time.Unix(int64(vo.Validity.NotAfterMin), 0)
}

func (vo VerifiedOutput) Digest() [32]byte {
	h := sha256.New()
	h.Write(vo.ToBytes())
	bz := h.Sum(nil)
	var digest [32]byte
	copy(digest[:], bz)
	return digest
}

// TCBStatus represents the status of the TCB.
type ValidityIntersection struct {
	NotBeforeMax uint64
	NotAfterMin  uint64
}

func (vi ValidityIntersection) ValidateTime(tm time.Time) bool {
	t := uint64(tm.Unix())
	return vi.NotBeforeMax <= t && t <= vi.NotAfterMin
}

type QuoteBody = pcs.SgxReport

func ParseDCAPVerifierCommit(raw []byte) (*VerifiedOutput, error) {
	version := uint16(raw[0])<<8 | uint16(raw[1])
	if version != DCAPQuoteVerifierVersion {
		return nil, fmt.Errorf("unexpected version: %d", version)
	}
	quoteVersion := uint16(raw[2])<<8 | uint16(raw[3])
	teeType := uint32(raw[4])<<24 | uint32(raw[5])<<16 | uint32(raw[6])<<8 | uint32(raw[7])
	tcbStatus := TCBStatus(raw[8])
	var fmspc [6]byte
	copy(fmspc[:], raw[9:15])
	var sgxIntelRootCAHash [32]byte
	copy(sgxIntelRootCAHash[:], raw[15:47])
	validity := ValidityIntersection{
		NotBeforeMax: binary.BigEndian.Uint64(raw[47:55]),
		NotAfterMin:  binary.BigEndian.Uint64(raw[55:63]),
	}
	var report pcs.SgxReport
	err := report.UnmarshalBinary(raw[63:])
	if err != nil {
		return nil, err
	}
	packer := abi.Arguments{
		{Type: advisoryIdsABI},
	}
	advisoryIds, err := packer.UnpackValues(raw[63+len(report.Raw()):])
	if err != nil {
		return nil, err
	}
	return &VerifiedOutput{
		Version:            version,
		QuoteVersion:       quoteVersion,
		TeeType:            teeType,
		TcbStatus:          tcbStatus,
		Fmspc:              fmspc,
		SGXIntelRootCAHash: sgxIntelRootCAHash,
		Validity:           validity,
		QuoteBody:          report,
		AdvisoryIds:        advisoryIds[0].([]string),
	}, nil
}

func (o *VerifiedOutput) ToBytes() []byte {
	bz := make([]byte, 63)
	bz[0] = byte(o.Version >> 8)
	bz[1] = byte(o.Version)
	bz[2] = byte(o.QuoteVersion >> 8)
	bz[3] = byte(o.QuoteVersion)
	bz[4] = byte(o.TeeType >> 24)
	bz[5] = byte(o.TeeType >> 16)
	bz[6] = byte(o.TeeType >> 8)
	bz[7] = byte(o.TeeType)
	bz[8] = o.TcbStatus.AsUint8()
	copy(bz[9:15], o.Fmspc[:])
	copy(bz[15:47], o.SGXIntelRootCAHash[:])
	binary.BigEndian.PutUint64(bz[47:55], o.Validity.NotBeforeMax)
	binary.BigEndian.PutUint64(bz[55:63], o.Validity.NotAfterMin)
	qbz, err := o.QuoteBody.MarshalBinary()
	if err != nil {
		panic(err)
	}
	bz = append(bz, qbz...)
	packer := abi.Arguments{
		{Type: advisoryIdsABI},
	}
	advisoryIds := []interface{}{o.AdvisoryIds}
	abz, err := packer.PackValues(advisoryIds)
	if err != nil {
		panic(err)
	}
	bz = append(bz, abz...)
	return bz
}

type ZKDCAPVerifierInfo struct {
	ZKVMType  ZKVMType
	ProgramID [32]byte
}

func (vi *ZKDCAPVerifierInfo) ToBytes() [64]byte {
	var bz [64]byte
	bz[0] = byte(vi.ZKVMType)
	copy(bz[32:], vi.ProgramID[:])
	return bz
}

func ParseZKDCAPVerifierInfo(raw []byte) (*ZKDCAPVerifierInfo, error) {
	if len(raw) != 64 {
		return nil, fmt.Errorf("invalid ZKDCAPVerifierInfo length: %d", len(raw))
	}
	zkvmType := ZKVMType(raw[0])
	var programID [32]byte
	copy(programID[:], raw[32:])
	return &ZKDCAPVerifierInfo{
		ZKVMType:  zkvmType,
		ProgramID: programID,
	}, nil
}
