package dcap

import (
	"fmt"
	"reflect"
	"unsafe"

	"github.com/oasisprotocol/oasis-core/go/common/sgx"
	"github.com/oasisprotocol/oasis-core/go/common/sgx/pcs"
)

const (
	UpToDate TCBStatus = iota
	OutOfDate
	Revoked
	ConfigurationNeeded
	OutOfDateConfigurationNeeded
	SWHardeningNeeded
	ConfigurationAndSWHardeningNeeded
)

const (
	TEETypeSGX = 0
	QEVersion3 = 3
)

var (
	unsafeAllowDebugEnclaves bool
)

func SetAllowDebugEnclaves() {
	unsafeAllowDebugEnclaves = true
}

func UnsetAllowDebugEnclaves() {
	unsafeAllowDebugEnclaves = false
}

func GetAllowDebugEnclaves() bool {
	return unsafeAllowDebugEnclaves
}

type TCBStatus uint8

func (s TCBStatus) AsUint8() uint8 {
	return uint8(s)
}

func (s TCBStatus) String() string {
	switch s {
	case UpToDate:
		return "UpToDate"
	case OutOfDate:
		return "OutOfDate"
	case Revoked:
		return "Revoked"
	case ConfigurationNeeded:
		return "ConfigurationNeeded"
	case OutOfDateConfigurationNeeded:
		return "OutOfDateConfigurationNeeded"
	case SWHardeningNeeded:
		return "SWHardeningNeeded"
	case ConfigurationAndSWHardeningNeeded:
		return "ConfigurationAndSWHardeningNeeded"
	default:
		return "Unrecognized"
	}
}

func TCBStatusFromString(s string) TCBStatus {
	switch s {
	case "UpToDate":
		return UpToDate
	case "OutOfDate":
		return OutOfDate
	case "Revoked":
		return Revoked
	case "ConfigurationNeeded":
		return ConfigurationNeeded
	case "OutOfDateConfigurationNeeded":
		return OutOfDateConfigurationNeeded
	case "SWHardeningNeeded":
		return SWHardeningNeeded
	case "ConfigurationAndSWHardeningNeeded":
		return ConfigurationAndSWHardeningNeeded
	default:
		panic(fmt.Sprintf("unrecognized TCB status: %s", s))
	}
}

func ParseQuote(raw []byte) (*pcs.Quote, error) {
	quote := new(pcs.Quote)
	err := quote.UnmarshalBinary(raw)
	if err != nil {
		return nil, err
	}
	return quote, nil
}

func GetSgxReportFromQuote(quote *pcs.Quote) (*pcs.SgxReport, error) {
	rb := reflect.ValueOf(quote).Elem().FieldByName("reportBody")
	if !rb.IsValid() {
		return nil, fmt.Errorf("quote does not have a reportBody field")
	}
	reportBody := *(*pcs.ReportBody)(unsafe.Pointer(rb.UnsafeAddr()))
	report, ok := reportBody.(*pcs.SgxReport)
	if !ok {
		return nil, fmt.Errorf("unexpected report body type: %T", reportBody)
	}
	return report, nil
}

func GetAttributesFromSgxReport(report *pcs.SgxReport) (*sgx.Attributes, error) {
	attr := reflect.ValueOf(report).Elem().FieldByName("attributes")
	if !attr.IsValid() {
		return nil, fmt.Errorf("report does not have an attributes field")
	}
	attributes := *(*sgx.Attributes)(unsafe.Pointer(attr.UnsafeAddr()))
	return &attributes, nil
}
