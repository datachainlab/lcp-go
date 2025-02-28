package enclave

import (
	"bytes"
	"time"

	"github.com/datachainlab/lcp-go/sgx/dcap"
	"github.com/ethereum/go-ethereum/common"
	"github.com/gogo/protobuf/jsonpb"
	"github.com/oasisprotocol/oasis-core/go/common/sgx/pcs"
)

func (eki *EnclaveKeyInfo) GetExpiredAt(keyExpiration time.Duration) time.Time {
	switch v := eki.KeyInfo.(type) {
	case *EnclaveKeyInfo_Ias:
		return time.Unix(int64(v.Ias.AttestationTime), 0).Add(keyExpiration)
	case *EnclaveKeyInfo_Dcap:
		if v.Dcap.Validity == nil {
			panic("GetExpiredAt: DCAP validity is nil")
		}
		return calculateDCAPKeyExpiration(*v.Dcap.Validity, keyExpiration)
	case *EnclaveKeyInfo_Zkdcap:
		if v.Zkdcap.Dcap.Validity == nil {
			panic("GetExpiredAt: zkDCAP validity is nil")
		}
		return calculateDCAPKeyExpiration(*v.Zkdcap.Dcap.Validity, keyExpiration)
	default:
		panic("GetAttestationTime: unexpected type")
	}
}

func calculateDCAPKeyExpiration(validity Validity, keyExpiration time.Duration) time.Time {
	notAfter := time.Unix(int64(validity.NotAfter), 0)
	if keyExpiration == 0 {
		return notAfter
	}
	tm := time.Unix(int64(validity.NotBefore), 0).Add(keyExpiration)
	if tm.After(notAfter) {
		return notAfter
	}
	return tm
}

func (eki *EnclaveKeyInfo) GetEnclaveKeyAddress() common.Address {
	switch v := eki.KeyInfo.(type) {
	case *EnclaveKeyInfo_Ias:
		return common.Address(v.Ias.EnclaveKeyAddress)
	case *EnclaveKeyInfo_Dcap:
		return common.Address(v.Dcap.EnclaveKeyAddress)
	case *EnclaveKeyInfo_Zkdcap:
		return common.Address(v.Zkdcap.Dcap.EnclaveKeyAddress)
	default:
		panic("GetEnclaveKeyAddress: unexpected type")
	}
}

func (eki *EnclaveKeyInfo) MarshalJSON() ([]byte, error) {
	buf := new(bytes.Buffer)
	marshaler := jsonpb.Marshaler{}
	if err := marshaler.Marshal(buf, eki); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (eki *EnclaveKeyInfo) UnmarshalJSON(data []byte) error {
	return jsonpb.Unmarshal(bytes.NewReader(data), eki)
}

func (eki *DCAPEnclaveKeyInfo) GetQuote() (*pcs.Quote, error) {
	return dcap.ParseQuote(eki.Quote)
}

func (eki *DCAPEnclaveKeyInfo) GetReportData() ([64]byte, error) {
	var reportData [64]byte
	quote, err := eki.GetQuote()
	if err != nil {
		return reportData, err
	}
	report, err := dcap.GetSgxReportFromQuote(quote)
	if err != nil {
		return reportData, err
	}
	copy(reportData[:], report.ReportData())
	return reportData, nil
}

func (m *Risc0ZKVMProof) GetProof() []byte {
	var proof []byte
	proof = append(proof, m.Selector...)
	proof = append(proof, m.Seal...)
	return proof
}
