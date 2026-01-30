package elcupdater

import (
	"context"
	"fmt"
	"strings"

	ibcexported "github.com/cosmos/ibc-go/v8/modules/core/exported"
	elcupdater_grpc "github.com/datachainlab/lcp-go/relay/elcupdater/grpc"
	elcupdater_storage "github.com/datachainlab/lcp-go/relay/elcupdater/storage"
	"github.com/hyperledger-labs/yui-relayer/core"
	"github.com/hyperledger-labs/yui-relayer/log"
)

func GetClientStateHeight(ctx context.Context, counterparty core.Chain, height ibcexported.Height) (ibcexported.Height, error) {
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

// GetUpdateClientResultsFromGRPC retrieves UpdateClientResults from gRPC server using height range and returns its updateClientResults property
func GetUpdateClientResultsFromGRPC(ctx context.Context, logger *log.RelayLogger, grpcAddress string, targetChain core.Chain, counterparty core.FinalityAwareChain, latestFinalizedHeader core.Header) ([]*elcupdater_storage.UpdateClientResult, error) {
	logger.InfoContext(ctx, "using getUpdateClientResults gRPC server", "address", grpcAddress)

	// Get chain ID from target chain and counterparty chain
	chainID := targetChain.ChainID()
	counterpartyChainID := counterparty.ChainID()

	// Get sequentialRecords by height range
	counterpartyLatestHeight, err := counterparty.LatestHeight(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get latest height: %w", err)
	}
	fromHeight, err := GetClientStateHeight(ctx, counterparty, counterpartyLatestHeight)
	if err != nil {
		return nil, fmt.Errorf("failed to get client state height from counterparty chain: %w", err)
	}

	records, err := elcupdater_grpc.GetSequentialRecords(ctx, grpcAddress, chainID, counterpartyChainID, fromHeight, latestFinalizedHeader.GetHeight())
	if err != nil {
		return nil, fmt.Errorf("failed to GetSequentialRecords: %w", err)
	}

	var results []*elcupdater_storage.UpdateClientResult
	var heights []string
	for _, record := range records {
		heights = append(heights, fmt.Sprintf("%d-%d", record.ToHeight.RevisionNumber, record.ToHeight.RevisionHeight))
		results = append(results, record.UpdateClientResults...)
	}
	logger.InfoContext(ctx, "retrieved records from gRPC server",
		"chain_id", chainID,
		"counterparty_chain_id", counterpartyChainID,
		"heights", strings.Join(heights, ", "),
	)

	return results, nil
}
