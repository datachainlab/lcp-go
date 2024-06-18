package ias

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/oasisprotocol/oasis-core/go/common/sgx/ias"
	"github.com/stretchr/testify/require"
)

type endorsedAttestationVerificationReport struct {
	AVR         string `json:"avr"`
	Signature   []byte `json:"signature"`
	SigningCert []byte `json:"signing_cert"`
}

func TestReportVerification(t *testing.T) {
	type testCase struct {
		path string
		ek   common.Address
		op   common.Address
	}

	ias.SetAllowDebugEnclaves()
	defer ias.UnsetAllowDebugEnclaves()

	var testCases = []testCase{
		{
			"../../testdata/001-avr",
			common.HexToAddress("0x836Fec0cC99Ed0242ed02fBAAb648652B2372E41"),
			common.Address{},
		},
		{
			"../../testdata/002-avr",
			common.HexToAddress("0xC9f79d5de52dbe84120055FF286642C5c328466e"),
			common.HexToAddress("0xcb96F8d6C2d543102184d679D7829b39434E4EEc"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.path, func(t *testing.T) {
			bz, err := os.ReadFile(tc.path)
			require.NoError(t, err)

			var eavr endorsedAttestationVerificationReport
			require.NoError(t, json.Unmarshal(bz, &eavr))

			require.NoError(t, VerifyReport([]byte(eavr.AVR), eavr.Signature, eavr.SigningCert, time.Now()))
			avr, err := ParseAndValidateAVR([]byte(eavr.AVR))
			require.NoError(t, err)

			quote, err := avr.Quote()
			require.NoError(t, err)
			ek, operator, err := GetEKAndOperator(quote)
			require.NoError(t, err)
			require.Equal(t, tc.ek, ek)
			require.Equal(t, tc.op, operator)
		})
	}
}
