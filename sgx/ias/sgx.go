package ias

import (
	"crypto/x509"
	"fmt"
	"time"

	"github.com/datachainlab/lcp-go/sgx"
	"github.com/ethereum/go-ethereum/common"
	"github.com/oasisprotocol/oasis-core/go/common/sgx/ias"
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
)

type AttestationVerificationReport struct {
	ias.AttestationVerificationReport
}

// GetTimestamp returns the timestamp of attestation.
// The timestamp is truncated to seconds.
func (avr AttestationVerificationReport) GetTimestamp() time.Time {
	tm, err := time.Parse(ias.TimestampFormat, avr.Timestamp)
	if err != nil {
		panic(err)
	}
	return tm.Truncate(time.Second)
}

func VerifyReport(report []byte, signature []byte, signingCertDer []byte, currentTime time.Time) error {
	rootCert := GetRARootCert()
	signingCert, err := x509.ParseCertificate(signingCertDer)
	if err != nil {
		return err
	}

	chains, err := signingCert.Verify(x509.VerifyOptions{
		Roots:       trustRARoots,
		CurrentTime: currentTime,
	})
	if err != nil {
		return err
	}

	if l := len(chains); l != 1 {
		return fmt.Errorf("unexpected chains length: %v", l)
	} else if l := len(chains[0]); l != 2 {
		return fmt.Errorf("unexpected certs length: %v", l)
	} else if !rootCert.Equal(chains[0][1]) {
		return fmt.Errorf("unexpected root cert: %v", chains[0][1])
	}

	if err = signingCert.CheckSignature(x509.SHA256WithRSA, report, signature); err != nil {
		return fmt.Errorf("failed to verify AVR signature: %w", err)
	}

	return nil
}

func ParseAndValidateAVR(report []byte) (*AttestationVerificationReport, error) {
	avr, err := ias.UnsafeDecodeAVR(report)
	if err != nil {
		return nil, err
	}
	return &AttestationVerificationReport{AttestationVerificationReport: *avr}, nil
}

func GetEKAndOperator(quote *ias.Quote) (common.Address, common.Address, error) {
	if err := quote.Verify(); err != nil {
		return common.Address{}, common.Address{}, err
	}
	return sgx.ParseReportData(quote.Report.ReportData)
}
