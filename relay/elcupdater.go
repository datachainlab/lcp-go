package relay

// The elcupdater package refers relay package to actually call updateClient functions,
// To avoid import cycle, functions about elcupdater are collectively located here.

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	ibcexported "github.com/cosmos/ibc-go/v8/modules/core/exported"
	elc_updater_grpc "github.com/datachainlab/lcp-go/relay/elcupdater/grpc"
	elcupdater_storage "github.com/datachainlab/lcp-go/relay/elcupdater/storage"
	"github.com/hyperledger-labs/yui-relayer/core"
	"github.com/hyperledger-labs/yui-relayer/log"
)

// Re-export types from storage package for backward compatibility
// type ELCUpdaterRecord = elc_updater_storage.ELCUpdateRecord
type UpdateClientResult = elcupdater_storage.UpdateClientResult

//type ELCUpdaterStorage = elc_updater_storage.ELCUpdateStorage

func (pr *Prover) updateClient(ctx context.Context, dstChain core.FinalityAwareChain, latestFinalizedHeader core.Header) ([]*UpdateClientResult, error) {
	// Use ELC updater gRPC server if configured (environment variable or config), otherwise use local implementation
	useGRPC, grpcAddress := pr.shouldUseELCUpdaterGRPC()
	if useGRPC {
		return getUpdateClientResultsFromGRPC(ctx, pr.getLogger(), grpcAddress, pr.originChain, dstChain, latestFinalizedHeader)
	} else {
		if err := pr.UpdateEKIIfNeeded(ctx, dstChain); err != nil {
			return nil, err
		}
		pr.getLogger().InfoContext(ctx, "using local updateELCForUpdateClient implementation")
		return pr.updateELCForUpdateClient(ctx, dstChain, latestFinalizedHeader)
	}
}

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

func GetClientStateHeight(ctx context.Context, counterparty core.FinalityAwareChain, height ibcexported.Height) (ibcexported.Height, error) {
	qCtx := core.NewQueryContext(ctx, height)

	csRes, err := counterparty.QueryClientState(qCtx)
	if err != nil {
		return nil, fmt.Errorf("failed to get client state: %w", err)
	}

	var cs ibcexported.ClientState
	if err := counterparty.Codec().UnpackAny(csRes.ClientState, &cs); err != nil {
		return nil, fmt.Errorf("failed to unpack client state: %w", err)
	}

	return cs.GetLatestHeight(), nil
}

// getUpdateClientResultsFromGRPC retrieves ELCUpdateResults from gRPC server using height range and returns its updateClientResults property
func getUpdateClientResultsFromGRPC(ctx context.Context, logger *log.RelayLogger, grpcAddress string, targetChain core.Chain, counterparty core.FinalityAwareChain, latestFinalizedHeader core.Header) ([]*UpdateClientResult, error) {
	logger.InfoContext(ctx, "using getUpdateClientResults gRPC server", "address", grpcAddress)

	// Get chain ID from target chain and counterparty chain
	chainID := targetChain.ChainID()
	counterpartyChainID := counterparty.ChainID()

	// Get sequential ELCUpdateRecords by height range
	counterpartyLatestFinalizedHeader, err := counterparty.GetLatestFinalizedHeader(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get latest finalized header: %w", err)
	}
	fromHeight, err := GetClientStateHeight(ctx, counterparty, counterpartyLatestFinalizedHeader.GetHeight())
	if err != nil {
		return nil, fmt.Errorf("failed to get client state height from counterparty chain: %w", err)
	}

	records, err := elc_updater_grpc.GetSequentialRecords(ctx, grpcAddress, chainID, counterpartyChainID, fromHeight, latestFinalizedHeader.GetHeight())
	if err != nil {
		return nil, fmt.Errorf("failed to GetSequentialRecords: %w", err)
	}

	var results []*UpdateClientResult
	var heights []string
	for _, record := range records {
		heights = append(heights, fmt.Sprintf("%d-%d", record.ToHeight.RevisionNumber, record.ToHeight.RevisionHeight))
		results = append(results, record.UpdateClientResults...)
	}
	logger.InfoContext(ctx, "retrieved ELCUpdate records from gRPC server",
		"chain_id", chainID,
		"counterparty_chain_id", counterpartyChainID,
		"heights", strings.Join(heights, ", "),
	)

	return results, nil
}
