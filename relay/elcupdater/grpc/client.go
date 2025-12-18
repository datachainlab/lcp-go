package grpc

import (
	"context"
	"fmt"

	"github.com/cosmos/cosmos-sdk/codec"
	"github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/ibc-go/v8/modules/core/exported"
	elc_updater_logger "github.com/datachainlab/lcp-go/relay/elcupdater/logger"
	elc_updater_storage "github.com/datachainlab/lcp-go/relay/elcupdater/storage"
	"github.com/google/uuid"
	"github.com/hyperledger-labs/yui-relayer/core"
	"github.com/hyperledger-labs/yui-relayer/log"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// GetSequentialRecords retrieves sequential ELCUpdateRecords from gRPC server
// If toHeight is not nil, stops when reaching a record with that ToHeight
func GetSequentialRecords(ctx context.Context, grpcAddress string, chainID string, counterpartyChainID string, fromHeight exported.Height, toHeight exported.Height) ([]*elc_updater_storage.ELCUpdateRecord, error) {
	requestID := uuid.Must(uuid.NewV7()).String()
	logger := log.RelayLogger{
		Logger: elc_updater_logger.GetELCUpdaterLogger(ctx).With(
			"function", "GetSequentialRecords",
			"request_id", requestID,
			"grpc_address", grpcAddress,
			"chain_id", chainID,
			"counterparty_chain_id", counterpartyChainID,
			"from_height", fmt.Sprintf("%d-%d", fromHeight.GetRevisionNumber(), fromHeight.GetRevisionHeight()),
		),
	}

	logger.InfoContext(ctx, "GetSequentialRecords request started")

	if grpcAddress == "" {
		logger.ErrorContext(ctx, "GetSequentialRecords request failed - no gRPC address", fmt.Errorf("ELCUpdater gRPC address not provided"))
		return nil, fmt.Errorf("ELCUpdater gRPC address not provided")
	}

	// Connect to ELCUpdater gRPC server
	conn, err := grpc.NewClient(grpcAddress,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithStatsHandler(otelgrpc.NewClientHandler()),
	)
	if err != nil {
		logger.ErrorContext(ctx, "GetSequentialRecords request failed - connection error", err)
		return nil, fmt.Errorf("failed to connect to ELCUpdater gRPC server: %w", err)
	}
	defer conn.Close()

	client := NewELCUpdaterServiceClient(conn)

	// Request sequential ELCUpdate records
	req := &GetSequentialRecordsRequest{
		ChainId:             chainID,
		CounterpartyChainId: counterpartyChainID,
		FromHeight:          ConvertHeightFromIbcToPb(fromHeight),
		ToHeight:            ConvertHeightFromIbcToPb(toHeight),
		RequestId:           requestID,
	}

	resp, err := client.GetSequentialRecords(ctx, req)
	if err != nil {
		logger.ErrorContext(ctx, "GetSequentialRecords request failed - gRPC call error", err)
		return nil, fmt.Errorf("failed to GetSequentialRecords from gRPC server: %w", err)
	}

	// Convert gRPC response to storage ELCUpdateRecord slice
	var records []*elc_updater_storage.ELCUpdateRecord
	for _, pbRecord := range resp.Records {
		records = append(records, ConvertELCUpdateRecordFromPbToDb(pbRecord))
	}

	logger.InfoContext(ctx, "GetSequentialRecords request completed successfully",
		"records_count", len(records))

	return records, nil
}

// GetLatestRecord retrieves the latest ELCUpdate record from gRPC server
func GetLatestRecord(ctx context.Context, grpcAddress string, chainID string, counterpartyChainID string) (*elc_updater_storage.ELCUpdateRecord, error) {
	requestID := uuid.Must(uuid.NewV7()).String()
	logger := log.RelayLogger{
		Logger: elc_updater_logger.GetELCUpdaterLogger(ctx).With(
			"function", "GetLatestRecord",
			"request_id", requestID,
			"grpc_address", grpcAddress,
			"chain_id", chainID,
			"counterparty_chain_id", counterpartyChainID,
		),
	}

	logger.InfoContext(ctx, "GetLatestRecord request started")
	if grpcAddress == "" {
		logger.ErrorContext(ctx, "GetLatestRecord request failed - no gRPC address", fmt.Errorf("ELCUpdater gRPC address not provided"))
		return nil, fmt.Errorf("ELCUpdater gRPC address not provided")
	}

	// Connect to ELCUpdate gRPC server
	conn, err := grpc.NewClient(grpcAddress,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithStatsHandler(otelgrpc.NewClientHandler()),
	)
	if err != nil {
		logger.ErrorContext(ctx, "GetLatestELCUpdate request failed - connection error", err)
		return nil, fmt.Errorf("failed to connect to ELCUpdate gRPC server: %w", err)
	}
	defer conn.Close()

	client := NewELCUpdaterServiceClient(conn)

	// Request latest ELCUpdate record
	req := &GetLatestRecordRequest{
		ChainId:             chainID,
		CounterpartyChainId: counterpartyChainID,
		RequestId:           requestID,
	}

	resp, err := client.GetLatestRecord(ctx, req)
	if err != nil {
		logger.ErrorContext(ctx, "GetLatestRecord request failed - gRPC call error", err)
		return nil, fmt.Errorf("failed to GetLatestRecord from gRPC server: %w", err)
	}

	if !resp.Found || resp.Record == nil {
		logger.InfoContext(ctx, "GetLatestRecord request completed - no record found",
			"found", resp.Found, "record", resp.Record != nil)
		return nil, nil // No record found
	}

	// Convert gRPC response to storage ELCUpdateRecord
	record := ConvertELCUpdateRecordFromPbToDb(resp.Record)

	logger.InfoContext(ctx, "GetLatestRecord request completed successfully",
		"found", true,
		"record_from_height", fmt.Sprintf("%d-%d", record.FromHeight.RevisionNumber, record.FromHeight.RevisionHeight),
		"record_to_height", fmt.Sprintf("%d-%d", record.ToHeight.RevisionNumber, record.ToHeight.RevisionHeight))

	return record, nil
}

// GetLatestFinalizedHeader retrieves the latest finalized header from gRPC server
func GetLatestFinalizedHeader(ctx context.Context, grpcAddress string, chainID string, counterpartyChainID string, codec codec.ProtoCodecMarshaler) (core.Header, error) {
	latestRecord, err := GetLatestRecord(ctx, grpcAddress, chainID, counterpartyChainID)
	if err != nil {
		return nil, err
	}
	if latestRecord == nil {
		return nil, nil
	}

	// Deserialize latest finalized header bytes using Any
	var anyMsg types.Any
	if err := codec.Unmarshal(latestRecord.LatestFinalizedHeader, &anyMsg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal latest finalized header bytes: %w", err)
	}

	// First, extract as exported.ClientMessage (the standard IBC interface)
	var clientMessage exported.ClientMessage
	if err := codec.UnpackAny(&anyMsg, &clientMessage); err != nil {
		return nil, fmt.Errorf("failed to unpack Any to ClientMessage: %w", err)
	}

	// Check if the ClientMessage also implements core.Header
	header, ok := clientMessage.(core.Header)
	if !ok {
		return nil, fmt.Errorf("ClientMessage does not implement core.Header interface, got type: %T", clientMessage)
	}

	return header, nil
}
