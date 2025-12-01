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

// GetLatestFinalizedHeader retrieves the latest finalized header from gRPC server
func GetLatestFinalizedHeader(ctx context.Context, grpcAddress string, chainID string, counterpartyChainID string, codec codec.ProtoCodecMarshaler) (core.Header, error) {
	logger := shfu_logger.GetSHFULogger(ctx)
	requestID := uuid.Must(uuid.NewV7()).String()

	logger.InfoContext(ctx, "GetLatestFinalizedHeader request started",
		"request_id", requestID,
		"grpc_address", grpcAddress,
		"chain_id", chainID,
		"counterparty_chain_id", counterpartyChainID)

	if grpcAddress == "" {
		logger.ErrorContext(ctx, "GetLatestFinalizedHeader request failed - no gRPC address", fmt.Errorf("SHFU gRPC address not provided"),
			"request_id", requestID,
			"chain_id", chainID,
			"counterparty_chain_id", counterpartyChainID)
		return nil, fmt.Errorf("SHFU gRPC address not provided")
	}

	// Connect to SHFU gRPC server
	conn, err := grpc.DialContext(ctx, grpcAddress,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithUnaryInterceptor(otelgrpc.UnaryClientInterceptor()),
		grpc.WithStreamInterceptor(otelgrpc.StreamClientInterceptor()),
	)
	if err != nil {
		logger.ErrorContext(ctx, "GetLatestFinalizedHeader request failed - connection error", err,
			"request_id", requestID,
			"grpc_address", grpcAddress,
			"chain_id", chainID,
			"counterparty_chain_id", counterpartyChainID)
		return nil, fmt.Errorf("failed to connect to SHFU gRPC server: %w", err)
	}
	defer conn.Close()

	client := NewSHFUServiceClient(conn)

	// Request latest SHFU record
	req := &GetLatestSHFURequest{
		ChainId:             chainID,
		CounterpartyChainId: counterpartyChainID,
		RequestId:           requestID,
	}

	resp, err := client.GetLatestSHFU(ctx, req)
	if err != nil {
		logger.ErrorContext(ctx, "GetLatestFinalizedHeader request failed - gRPC call error", err,
			"request_id", requestID,
			"grpc_address", grpcAddress,
			"chain_id", chainID,
			"counterparty_chain_id", counterpartyChainID)
		return nil, fmt.Errorf("failed to get latest SHFU from gRPC server: %w", err)
	}

	if resp.Record == nil {
		logger.InfoContext(ctx, "GetLatestFinalizedHeader request completed - no record found",
			"request_id", requestID,
			"grpc_address", grpcAddress,
			"chain_id", chainID,
			"counterparty_chain_id", counterpartyChainID,
			"found", false)
		return nil, fmt.Errorf("no SHFU record found from gRPC server for chain %s (counterparty: %s)", chainID, counterpartyChainID)
	}

	// Deserialize latest finalized header bytes using Any
	var anyMsg types.Any
	if err := codec.Unmarshal(resp.Record.LatestFinalizedHeader, &anyMsg); err != nil {
		logger.ErrorContext(ctx, "GetLatestFinalizedHeader request failed - unmarshal error", err,
			"request_id", requestID,
			"grpc_address", grpcAddress,
			"chain_id", chainID,
			"counterparty_chain_id", counterpartyChainID)
		return nil, fmt.Errorf("failed to unmarshal latest finalized header bytes: %w", err)
	}

	// First, extract as exported.ClientMessage (the standard IBC interface)
	var clientMessage exported.ClientMessage
	if err := codec.UnpackAny(&anyMsg, &clientMessage); err != nil {
		logger.ErrorContext(ctx, "GetLatestFinalizedHeader request failed - unpack error", err,
			"request_id", requestID,
			"grpc_address", grpcAddress,
			"chain_id", chainID,
			"counterparty_chain_id", counterpartyChainID)
		return nil, fmt.Errorf("failed to unpack Any to ClientMessage: %w", err)
	}

	// Check if the ClientMessage also implements core.Header
	header, ok := clientMessage.(core.Header)
	if !ok {
		err := fmt.Errorf("ClientMessage does not implement core.Header interface, got type: %T", clientMessage)
		logger.ErrorContext(ctx, "GetLatestFinalizedHeader request failed - type assertion error", err,
			"request_id", requestID,
			"grpc_address", grpcAddress,
			"chain_id", chainID,
			"counterparty_chain_id", counterpartyChainID,
			"client_message_type", fmt.Sprintf("%T", clientMessage))
		return nil, err
	}

	logger.InfoContext(ctx, "GetLatestFinalizedHeader request completed successfully",
		"request_id", requestID,
		"grpc_address", grpcAddress,
		"chain_id", chainID,
		"counterparty_chain_id", counterpartyChainID,
		"found", true,
		"to_height", fmt.Sprintf("%d-%d", resp.Record.ToHeight.RevisionNumber, resp.Record.ToHeight.RevisionHeight))

	return header, nil
}

// GetSHFUByHeight retrieves SHFU record by height range from gRPC server
func GetSHFUByHeight(ctx context.Context, grpcAddress string, chainID string, counterpartyChainID string, toHeight exported.Height) (*shfu_storage.SHFURecord, error) {
	logger := shfu_logger.GetSHFULogger(ctx)
	requestID := uuid.Must(uuid.NewV7()).String()

	logger.InfoContext(ctx, "GetSHFUByHeight request started",
		"request_id", requestID,
		"grpc_address", grpcAddress,
		"chain_id", chainID,
		"counterparty_chain_id", counterpartyChainID,
		"to_height", fmt.Sprintf("%d-%d", toHeight.GetRevisionNumber(), toHeight.GetRevisionHeight()))

	if grpcAddress == "" {
		logger.ErrorContext(ctx, "GetSHFUByHeight request failed - no gRPC address", fmt.Errorf("SHFU gRPC address not provided"),
			"request_id", requestID,
			"chain_id", chainID,
			"counterparty_chain_id", counterpartyChainID,
			"to_height", fmt.Sprintf("%d-%d", toHeight.GetRevisionNumber(), toHeight.GetRevisionHeight()))
		return nil, fmt.Errorf("SHFU gRPC address not provided")
	}

	// Connect to SHFU gRPC server
	conn, err := grpc.DialContext(ctx, grpcAddress,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithUnaryInterceptor(otelgrpc.UnaryClientInterceptor()),
		grpc.WithStreamInterceptor(otelgrpc.StreamClientInterceptor()),
	)
	if err != nil {
		logger.ErrorContext(ctx, "GetSHFUByHeight request failed - connection error", err,
			"request_id", requestID,
			"grpc_address", grpcAddress,
			"chain_id", chainID,
			"counterparty_chain_id", counterpartyChainID,
			"to_height", fmt.Sprintf("%d-%d", toHeight.GetRevisionNumber(), toHeight.GetRevisionHeight()))
		return nil, fmt.Errorf("failed to connect to SHFU gRPC server: %w", err)
	}
	defer conn.Close()

	client := NewSHFUServiceClient(conn)

	// Request SHFU record by height range
	req := &GetSHFUByHeightRequest{
		ChainId:             chainID,
		CounterpartyChainId: counterpartyChainID,
		ToHeight:            ConvertHeightFromIbcToPb(toHeight),
		RequestId:           requestID,
	}

	resp, err := client.GetSHFUByHeight(ctx, req)
	if err != nil {
		logger.ErrorContext(ctx, "GetSHFUByHeight request failed - gRPC call error", err,
			"request_id", requestID,
			"grpc_address", grpcAddress,
			"chain_id", chainID,
			"counterparty_chain_id", counterpartyChainID,
			"to_height", fmt.Sprintf("%d-%d", toHeight.GetRevisionNumber(), toHeight.GetRevisionHeight()))
		return nil, fmt.Errorf("failed to get SHFU by height from gRPC server: %w", err)
	}

	if !resp.Found || resp.Record == nil {
		logger.InfoContext(ctx, "GetSHFUByHeight request completed - no record found",
			"request_id", requestID,
			"grpc_address", grpcAddress,
			"chain_id", chainID,
			"counterparty_chain_id", counterpartyChainID,
			"to_height", fmt.Sprintf("%d-%d", toHeight.GetRevisionNumber(), toHeight.GetRevisionHeight()),
			"found", false)
		return nil, nil // No record found
	}

	// Convert gRPC response to storage SHFURecord
	record := ConvertSHFURecordFromPbToDb(resp.Record)

	logger.InfoContext(ctx, "GetSHFUByHeight request completed successfully",
		"request_id", requestID,
		"grpc_address", grpcAddress,
		"chain_id", chainID,
		"counterparty_chain_id", counterpartyChainID,
		"to_height", fmt.Sprintf("%d-%d", toHeight.GetRevisionNumber(), toHeight.GetRevisionHeight()),
		"found", true,
		"record_to_height", fmt.Sprintf("%d-%d", record.ToHeight.RevisionNumber, record.ToHeight.RevisionHeight))

	return record, nil
}
