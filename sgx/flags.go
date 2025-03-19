package sgx

import (
	"github.com/datachainlab/lcp-go/sgx/dcap"
	"github.com/oasisprotocol/oasis-core/go/common/sgx/ias"
)

// SetAllowDebugEnclave will enable running and communicating with enclaves
// with debug flag enabled in AVR for the remainder of the process' lifetime.
func SetAllowDebugEnclaves() {
	ias.SetAllowDebugEnclaves()
	dcap.SetAllowDebugEnclaves()
}

// UnsetAllowDebugEnclave will disable running and communicating with enclaves
// with debug flag enabled in AVR for the remainder of the process' lifetime.
func UnsetAllowDebugEnclaves() {
	ias.UnsetAllowDebugEnclaves()
	dcap.UnsetAllowDebugEnclaves()
}
