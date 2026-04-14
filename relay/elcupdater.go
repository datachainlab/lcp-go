package relay

// The elcupdater package refers relay package to actually call updateClient functions,
// To avoid import cycle, functions about elcupdater are collectively located here.

import (
	"context"
	"fmt"
	"os"
	"strconv"

	"github.com/datachainlab/lcp-go/relay/elcupdater"
	elcupdater_grpc "github.com/datachainlab/lcp-go/relay/elcupdater/grpc"
	elcupdater_storage "github.com/datachainlab/lcp-go/relay/elcupdater/storage"
	"github.com/hyperledger-labs/yui-relayer/core"
)

// shouldUseELCUpdaterGRPC determines whether to use ELC updater gRPC server based on config and environment variable
// Environment variable YRLY_LCP_ELC_UPDATER_GRPC_ENABLE=true enables gRPC, disabled by default
func (pr *Prover) shouldUseELCUpdaterGRPC() (bool, string, error) {
	// Check if gRPC is enabled via environment variable
	envEnable, present := os.LookupEnv("YRLY_LCP_ELC_UPDATER_GRPC_ENABLE")
	if !present {
		return false, "", nil
	}
	b, err := strconv.ParseBool(envEnable)
	if err != nil {
		return false, "", fmt.Errorf("invalid value for YRLY_LCP_ELC_UPDATER_GRPC_ENABLE: %w", err)
	}
	if !b {
		// gRPC is explicitly disabled by the environment variable
		return false, "", nil
	}

	// Check if address is configured
	if pr.config.ElcUpdaterGrpcAddress == "" {
		// No address configured, cannot use gRPC
		return false, "", fmt.Errorf("elc_updater_grpc_address must be non-blank in prover config when YRLY_LCP_ELC_UPDATER_GRPC_ENABLE is enabled (got %q)", envEnable)
	}

	// Address configured and gRPC enabled, use gRPC
	return true, pr.config.ElcUpdaterGrpcAddress, nil
}

func (pr *Prover) updateClient(ctx context.Context, dstChain core.FinalityAwareChain, latestFinalizedHeader core.Header) ([]*elcupdater_storage.UpdateClientResult, error) {
	// Use ELC updater gRPC server if configured (environment variable and config), otherwise use local implementation
	useGRPC, grpcAddress, err := pr.shouldUseELCUpdaterGRPC()
	if err != nil {
		return nil, err
	}
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

func (pr *Prover) getEnclaveKeyAddressBytes(ctx context.Context, chainID string, counterpartyChainID string) ([]byte, error) {
	useGRPC, grpcAddress, err := pr.shouldUseELCUpdaterGRPC()
	if err != nil {
		return nil, err
	}
	if useGRPC {
		record, err := elcupdater_grpc.GetLatestRecord(ctx, grpcAddress, chainID, counterpartyChainID)
		if err != nil {
			pr.getLogger().ErrorContext(ctx, "failed to get latest ELCUpdateRecord from gRPC server", err)
			return nil, err
		}
		return record.UpdateClientResults[0].Signer, nil
	} else {
		return pr.activeEnclaveKey.GetEnclaveKeyAddress().Bytes(), nil
	}
}
