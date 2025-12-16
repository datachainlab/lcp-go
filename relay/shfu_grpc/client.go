package shfu_grpc

import (
	"context"
	"fmt"

	"github.com/cosmos/cosmos-sdk/codec"
	"github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/ibc-go/v8/modules/core/exported"
	"github.com/datachainlab/lcp-go/relay/shfu_logger"
	"github.com/datachainlab/lcp-go/relay/shfu_storage"
	"github.com/google/uuid"
	"github.com/hyperledger-labs/yui-relayer/core"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// GetSequentialSHFURecords retrieves sequential SHFU records from gRPC server
// If toHeight is not nil, stops when reaching a record with that ToHeight
func GetSequentialSHFURecords(ctx context.Context, grpcAddress string, chainID string, counterpartyChainID string, fromHeight exported.Height, toHeight exported.Height) ([]*shfu_storage.SHFURecord, error) {
	logger := shfu_logger.GetSHFULogger(ctx)
	requestID := uuid.Must(uuid.NewV7()).String()

	logger.InfoContext(ctx, "GetSequentialSHFURecords request started",
		"request_id", requestID,
		"grpc_address", grpcAddress,
		"chain_id", chainID,
		"counterparty_chain_id", counterpartyChainID,
		"from_height", fmt.Sprintf("%d-%d", fromHeight.GetRevisionNumber(), fromHeight.GetRevisionHeight()))

	if grpcAddress == "" {
		logger.ErrorContext(ctx, "GetSequentialSHFURecords request failed - no gRPC address", fmt.Errorf("SHFU gRPC address not provided"),
			"request_id", requestID,
			"chain_id", chainID,
			"counterparty_chain_id", counterpartyChainID,
			"from_height", fmt.Sprintf("%d-%d", fromHeight.GetRevisionNumber(), fromHeight.GetRevisionHeight()))
		return nil, fmt.Errorf("SHFU gRPC address not provided")
	}

	// Connect to SHFU gRPC server
	conn, err := grpc.NewClient(grpcAddress,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithUnaryInterceptor(otelgrpc.UnaryClientInterceptor()),
		grpc.WithStreamInterceptor(otelgrpc.StreamClientInterceptor()),
	)
	if err != nil {
		logger.ErrorContext(ctx, "GetSequentialSHFURecords request failed - connection error", err,
			"request_id", requestID,
			"grpc_address", grpcAddress,
			"chain_id", chainID,
			"counterparty_chain_id", counterpartyChainID,
			"from_height", fmt.Sprintf("%d-%d", fromHeight.GetRevisionNumber(), fromHeight.GetRevisionHeight()))
		return nil, fmt.Errorf("failed to connect to SHFU gRPC server: %w", err)
	}
	defer conn.Close()
	conn.Connect()

	client := NewSHFUServiceClient(conn)

	// Request sequential SHFU records
	req := &GetSequentialSHFURecordsRequest{
		ChainId:             chainID,
		CounterpartyChainId: counterpartyChainID,
		FromHeight:          ConvertHeightFromIbcToPb(fromHeight),
		ToHeight:            ConvertHeightFromIbcToPb(toHeight),
		RequestId:           requestID,
	}

	resp, err := client.GetSequentialSHFURecords(ctx, req)
	if err != nil {
		logger.ErrorContext(ctx, "GetSequentialSHFURecords request failed - gRPC call error", err,
			"request_id", requestID,
			"grpc_address", grpcAddress,
			"chain_id", chainID,
			"counterparty_chain_id", counterpartyChainID,
			"from_height", fmt.Sprintf("%d-%d", fromHeight.GetRevisionNumber(), fromHeight.GetRevisionHeight()))
		return nil, fmt.Errorf("failed to get sequential SHFU records from gRPC server: %w", err)
	}

	// Convert gRPC response to storage SHFURecord slice
	var records []*shfu_storage.SHFURecord
	for _, pbRecord := range resp.Records {
		records = append(records, ConvertSHFURecordFromPbToDb(pbRecord))
	}

	logger.InfoContext(ctx, "GetSequentialSHFURecords request completed successfully",
		"request_id", requestID,
		"grpc_address", grpcAddress,
		"chain_id", chainID,
		"counterparty_chain_id", counterpartyChainID,
		"from_height", fmt.Sprintf("%d-%d", fromHeight.GetRevisionNumber(), fromHeight.GetRevisionHeight()),
		"records_count", len(records))

	return records, nil
}

// GetLatestSHFU retrieves the latest SHFU record from gRPC server
func GetLatestSHFU(ctx context.Context, grpcAddress string, chainID string, counterpartyChainID string) (*shfu_storage.SHFURecord, error) {
	logger := shfu_logger.GetSHFULogger(ctx)
	requestID := uuid.Must(uuid.NewV7()).String()

	logger.InfoContext(ctx, "GetLatestSHFU request started",
		"request_id", requestID,
		"grpc_address", grpcAddress,
		"chain_id", chainID,
		"counterparty_chain_id", counterpartyChainID)

	if grpcAddress == "" {
		logger.ErrorContext(ctx, "GetLatestSHFU request failed - no gRPC address", fmt.Errorf("SHFU gRPC address not provided"),
			"request_id", requestID,
			"chain_id", chainID,
			"counterparty_chain_id", counterpartyChainID)
		return nil, fmt.Errorf("SHFU gRPC address not provided")
	}

	// Connect to SHFU gRPC server
	conn, err := grpc.NewClient(grpcAddress,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithUnaryInterceptor(otelgrpc.UnaryClientInterceptor()),
		grpc.WithStreamInterceptor(otelgrpc.StreamClientInterceptor()),
	)
	if err != nil {
		logger.ErrorContext(ctx, "GetLatestSHFU request failed - connection error", err,
			"request_id", requestID,
			"grpc_address", grpcAddress,
			"chain_id", chainID,
			"counterparty_chain_id", counterpartyChainID)
		return nil, fmt.Errorf("failed to connect to SHFU gRPC server: %w", err)
	}
	defer conn.Close()
	conn.Connect()

	client := NewSHFUServiceClient(conn)

	// Request latest SHFU record
	req := &GetLatestSHFURequest{
		ChainId:             chainID,
		CounterpartyChainId: counterpartyChainID,
		RequestId:           requestID,
	}

	resp, err := client.GetLatestSHFU(ctx, req)
	if err != nil {
		logger.ErrorContext(ctx, "GetLatestSHFU request failed - gRPC call error", err,
			"request_id", requestID,
			"grpc_address", grpcAddress,
			"chain_id", chainID,
			"counterparty_chain_id", counterpartyChainID)
		return nil, fmt.Errorf("failed to get latest SHFU record from gRPC server: %w", err)
	}

	if !resp.Found || resp.Record == nil {
		logger.InfoContext(ctx, "GetLatestSHFU request completed - no record found",
			"request_id", requestID,
			"grpc_address", grpcAddress,
			"chain_id", chainID,
			"counterparty_chain_id", counterpartyChainID,
			"found", false)
		return nil, nil // No record found
	}

	// Convert gRPC response to storage SHFURecord
	record := ConvertSHFURecordFromPbToDb(resp.Record)

	logger.InfoContext(ctx, "GetLatestSHFU request completed successfully",
		"request_id", requestID,
		"grpc_address", grpcAddress,
		"chain_id", chainID,
		"counterparty_chain_id", counterpartyChainID,
		"found", true,
		"record_from_height", fmt.Sprintf("%d-%d", record.FromHeight.RevisionNumber, record.FromHeight.RevisionHeight),
		"record_to_height", fmt.Sprintf("%d-%d", record.ToHeight.RevisionNumber, record.ToHeight.RevisionHeight))

	return record, nil
}

// GetLatestFinalizedHeader retrieves the latest finalized header from gRPC server
func GetLatestFinalizedHeader(ctx context.Context, grpcAddress string, chainID string, counterpartyChainID string, codec codec.ProtoCodecMarshaler) (core.Header, error) {
	latestRecord, err := GetLatestSHFU(ctx, grpcAddress, chainID, counterpartyChainID)
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
