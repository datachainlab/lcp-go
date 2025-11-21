package shfu_grpc

import (
	"context"
	"fmt"

	"github.com/cosmos/cosmos-sdk/codec"
	"github.com/cosmos/cosmos-sdk/codec/types"
	clienttypes "github.com/cosmos/ibc-go/v8/modules/core/02-client/types"
	"github.com/cosmos/ibc-go/v8/modules/core/exported"
	"github.com/datachainlab/lcp-go/relay/shfu_storage"
	"github.com/hyperledger-labs/yui-relayer/core"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// GetLatestFinalizedHeader retrieves the latest finalized header from gRPC server
func GetLatestFinalizedHeader(ctx context.Context, grpcAddress string, chainID string, counterpartyChainID string, codec codec.ProtoCodecMarshaler) (core.Header, error) {
	if grpcAddress == "" {
		return nil, fmt.Errorf("SHFU gRPC address not provided")
	}

	// Connect to SHFU gRPC server
	conn, err := grpc.DialContext(ctx, grpcAddress,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithUnaryInterceptor(otelgrpc.UnaryClientInterceptor()),
		grpc.WithStreamInterceptor(otelgrpc.StreamClientInterceptor()),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to SHFU gRPC server: %w", err)
	}
	defer conn.Close()

	client := NewSHFUServiceClient(conn)

	// Request latest SHFU record
	req := &GetLatestSHFURequest{
		ChainId:             chainID,
		CounterpartyChainId: counterpartyChainID,
	}

	resp, err := client.GetLatestSHFU(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to get latest SHFU from gRPC server: %w", err)
	}

	if resp.Record == nil {
		return nil, fmt.Errorf("no SHFU record found from gRPC server for chain %s (counterparty: %s)", chainID, counterpartyChainID)
	}

	// Deserialize latest finalized header bytes using Any
	var anyMsg types.Any
	if err := codec.Unmarshal(resp.Record.LatestFinalizedHeader, &anyMsg); err != nil {
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

func GetSHFUByHeight(ctx context.Context, grpcAddress string, chainID string, counterpartyChainID string, toHeight exported.Height) (*shfu_storage.SHFURecord, error) {
	fmt.Printf("zzz >GetSHFUByHeight called with grpcAddress=%s, chainID=%s, counterpartyChainID=%s, toHeight=%v\n", grpcAddress, chainID, counterpartyChainID, toHeight)
	res, err := GetSHFUByHeight0(ctx, grpcAddress, chainID, counterpartyChainID, toHeight)
	fmt.Printf("zzz <GetSHFUByHeight returned res=%v, err=%v\n", res, err)
	return res, err
}

// GetSHFUByHeight retrieves SHFU record by height range from gRPC server
func GetSHFUByHeight0(ctx context.Context, grpcAddress string, chainID string, counterpartyChainID string, toHeight exported.Height) (*shfu_storage.SHFURecord, error) {
	if grpcAddress == "" {
		return nil, fmt.Errorf("SHFU gRPC address not provided")
	}

	// Connect to SHFU gRPC server
	conn, err := grpc.DialContext(ctx, grpcAddress,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithUnaryInterceptor(otelgrpc.UnaryClientInterceptor()),
		grpc.WithStreamInterceptor(otelgrpc.StreamClientInterceptor()),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to SHFU gRPC server: %w", err)
	}
	defer conn.Close()

	client := NewSHFUServiceClient(conn)

	// Request SHFU record by height range
	req := &GetSHFUByHeightRequest{
		ChainId:             chainID,
		CounterpartyChainId: counterpartyChainID,
		ToHeight: &Height{
			RevisionNumber: toHeight.GetRevisionNumber(),
			RevisionHeight: toHeight.GetRevisionHeight(),
		},
	}

	resp, err := client.GetSHFUByHeight(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to get SHFU by height from gRPC server: %w", err)
	}

	if !resp.Found || resp.Record == nil {
		return nil, nil // No record found
	}

	// Convert gRPC response to storage SHFURecord
	record := &shfu_storage.SHFURecord{
		ChainID:             resp.Record.ChainId,
		CounterpartyChainID: resp.Record.CounterpartyChainId,
		ToHeight: clienttypes.Height{
			RevisionNumber: resp.Record.ToHeight.RevisionNumber,
			RevisionHeight: resp.Record.ToHeight.RevisionHeight,
		},
		ToHeightTime:          resp.Record.ToHeightTime,
		UpdatedAt:             resp.Record.UpdatedAt,
		LatestFinalizedHeader: resp.Record.LatestFinalizedHeader,
	}

	// Convert UpdateClientResults
	for _, grpcResult := range resp.Record.UpdateClientResults {
		result := &shfu_storage.UpdateClientResult{
			Message:   grpcResult.Message,
			Signature: grpcResult.Signature,
		}
		record.UpdateClientResults = append(record.UpdateClientResults, result)
	}

	return record, nil
}
