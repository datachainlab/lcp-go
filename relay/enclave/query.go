package enclave

import (
	"bytes"
	"time"

	"github.com/datachainlab/lcp-go/sgx/dcap"
	"github.com/ethereum/go-ethereum/common"
	"github.com/gogo/protobuf/jsonpb"
	"github.com/oasisprotocol/oasis-core/go/common/sgx/pcs"
)

func (eki *EnclaveKeyInfo) GetAttestationTime() time.Time {
	switch v := eki.KeyInfo.(type) {
	case *EnclaveKeyInfo_Ias:
		return time.Unix(int64(v.Ias.AttestationTime), 0)
	case *EnclaveKeyInfo_Dcap:
		return time.Unix(int64(v.Dcap.AttestationTime), 0)
	case *EnclaveKeyInfo_Zkdcap:
		return time.Unix(int64(v.Zkdcap.Dcap.AttestationTime), 0)
	default:
		panic("GetAttestationTime: unexpected type")
	}
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
