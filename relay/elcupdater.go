package relay

// The elcupdater package refers relay package to actually call updateClient functions,
// To avoid import cycle, functions about elcupdater are collectively located here.

import (
	"context"
	"os"
	"strconv"

	"github.com/datachainlab/lcp-go/relay/elcupdater"
	elcupdater_storage "github.com/datachainlab/lcp-go/relay/elcupdater/storage"
	"github.com/hyperledger-labs/yui-relayer/core"
)

// shouldUseELCUpdaterGRPC determines whether to use ELC updater gRPC server based on config and environment variable
// Environment variable YRLY_LCP_ELC_UPDATER_GRPC_ENABLE=yes enables gRPC, disabled by default
func (pr *Prover) shouldUseELCUpdaterGRPC() (bool, string) {
	// First check if address is configured
	if pr.config.ElcUpdaterGrpcAddress == "" {
		// No address configured, cannot use gRPC
		return false, ""
	}

	// Check if gRPC is enabled via environment variable
	envEnable := os.Getenv("YRLY_LCP_ELC_UPDATER_GRPC_ENABLE")
	if b, err := strconv.ParseBool(envEnable); err != nil || !b {
		// Environment variable is not true or is not set, gRPC disabled by default
		return false, ""
	}

	// Address configured and gRPC enabled, use gRPC
	return true, pr.config.ElcUpdaterGrpcAddress
}

func (pr *Prover) updateClient(ctx context.Context, dstChain core.FinalityAwareChain, latestFinalizedHeader core.Header) ([]*elcupdater_storage.UpdateClientResult, error) {
	// Use ELC updater gRPC server if configured (environment variable or config), otherwise use local implementation
	useGRPC, grpcAddress := pr.shouldUseELCUpdaterGRPC()
	if useGRPC {
		return elcupdater.GetUpdateClientResultsFromGRPC(ctx, pr.getLogger(), grpcAddress, pr.originChain, dstChain, latestFinalizedHeader)
	} else {
		if err := pr.UpdateEKIIfNeeded(ctx, dstChain); err != nil {
			return nil, err
		}
		pr.getLogger().InfoContext(ctx, "using local updateELCForUpdateClient implementation")
		return pr.updateELCForUpdateClient(ctx, dstChain, latestFinalizedHeader)
	}
}
