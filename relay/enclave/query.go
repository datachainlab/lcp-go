package enclave

import (
	"bytes"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/gogo/protobuf/jsonpb"
)

func (eki *EnclaveKeyInfo) GetAttestationTime() time.Time {
	switch v := eki.KeyInfo.(type) {
	case *EnclaveKeyInfo_Ias:
		return time.Unix(int64(v.Ias.AttestationTime), 0)
	case *EnclaveKeyInfo_Dcap:
		return time.Unix(int64(v.Dcap.AttestationTime), 0)
	default:
		panic("unexpected type")
	}
}

func (eki *EnclaveKeyInfo) GetEnclaveKeyAddress() common.Address {
	switch v := eki.KeyInfo.(type) {
	case *EnclaveKeyInfo_Ias:
		return common.Address(v.Ias.EnclaveKeyAddress)
	case *EnclaveKeyInfo_Dcap:
		return common.Address(v.Dcap.EnclaveKeyAddress)
	default:
		panic("unexpected type")
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
