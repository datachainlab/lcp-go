package ias

import (
	"crypto/x509"
	"fmt"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/oasisprotocol/oasis-core/go/common/sgx/ias"
)

const (
	ReportDataVersion uint8 = 1
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
	reportData := quote.Report.ReportData
	if reportData[0] != ReportDataVersion {
		return common.Address{}, common.Address{}, fmt.Errorf("unexpected report data version: %v", reportData[0])
	}
	ek := common.BytesToAddress(quote.Report.ReportData[1:21])
	operator := common.BytesToAddress(quote.Report.ReportData[21:41])
	return ek, operator, nil
}
