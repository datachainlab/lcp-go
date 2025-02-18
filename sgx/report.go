package sgx

import (
	"fmt"

	"github.com/ethereum/go-ethereum/common"
)

const (
	ReportDataVersion uint8 = 1
)

func ParseReportData(data [64]byte) (ek common.Address, operator common.Address, err error) {
	if data[0] != ReportDataVersion {
		return common.Address{}, common.Address{}, fmt.Errorf("unexpected report data version: %v", data[0])
	}
	return common.BytesToAddress(data[1:21]), common.BytesToAddress(data[21:41]), nil
}

func ParseReportData2(data []byte) (ek common.Address, operator common.Address, err error) {
	var reportData [64]byte
	if len(data) != 64 {
		return common.Address{}, common.Address{}, fmt.Errorf("unexpected report data length: %v", len(data))
	}
	copy(reportData[:], data)
	return ParseReportData(reportData)
}
