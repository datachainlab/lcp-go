package shfu_grpc

import (
	"context"
	"fmt"

	"github.com/datachainlab/lcp-go/relay/shfu_logger"
	"github.com/datachainlab/lcp-go/relay/shfu_storage"
)

// SHFUGRPCServer implements the gRPC SHFUServiceServer interface
type SHFUGRPCServer struct {
	storage shfu_storage.SHFUStorage
	UnimplementedSHFUServiceServer
}

// NewSHFUGRPCServer creates a new SHFUGRPCServer
func NewSHFUGRPCServer(storage shfu_storage.SHFUStorage) *SHFUGRPCServer {
	return &SHFUGRPCServer{
		UnimplementedSHFUServiceServer: UnimplementedSHFUServiceServer{},
		storage:                        storage,
	}
}

// GetLatestSHFU implements the gRPC service method
func (srv *SHFUGRPCServer) GetLatestSHFU(ctx context.Context, req *GetLatestSHFURequest) (*GetLatestSHFUResponse, error) {
	logger := shfu_logger.GetSHFULogger(ctx)

	logger.InfoContext(ctx, "GetLatestSHFU request started",
		"request_id", req.RequestId,
		"chain_id", req.ChainId,
		"counterparty_chain_id", req.CounterpartyChainId)

	// Get latest SHFU record from storage
	record, err := srv.storage.GetLatestSHFUForChain(ctx, req.ChainId, req.CounterpartyChainId)
	if err != nil {
		logger.ErrorContext(ctx, "GetLatestSHFU request failed", err,
			"request_id", req.RequestId,
			"chain_id", req.ChainId,
			"counterparty_chain_id", req.CounterpartyChainId)
		return nil, fmt.Errorf("failed to get latest SHFU: %w", err)
	}

	if record == nil {
		logger.InfoContext(ctx, "GetLatestSHFU request completed - no record found",
			"request_id", req.RequestId,
			"chain_id", req.ChainId,
			"counterparty_chain_id", req.CounterpartyChainId,
			"found", false)
		return &GetLatestSHFUResponse{Found: false}, nil
	}

	// Convert to protobuf message
	pbRecord := ConvertSHFURecordFromDbToPb(record)

	logger.InfoContext(ctx, "GetLatestSHFU request completed successfully",
		"request_id", req.RequestId,
		"chain_id", req.ChainId,
		"counterparty_chain_id", req.CounterpartyChainId,
		"found", true,
		"to_height", fmt.Sprintf("%d-%d", record.ToHeight.RevisionNumber, record.ToHeight.RevisionHeight))

	return &GetLatestSHFUResponse{Found: true, Record: pbRecord}, nil
}

// GetSHFUByHeight implements the gRPC service method to get SHFU record by height range
func (srv *SHFUGRPCServer) GetSHFUByHeight(ctx context.Context, req *GetSHFUByHeightRequest) (*GetSHFUByHeightResponse, error) {
	logger := shfu_logger.GetSHFULogger(ctx)

	logger.InfoContext(ctx, "GetSHFUByHeight request started",
		"request_id", req.RequestId,
		"chain_id", req.ChainId,
		"counterparty_chain_id", req.CounterpartyChainId,
		"to_height", fmt.Sprintf("%d-%d", req.ToHeight.RevisionNumber, req.ToHeight.RevisionHeight))

	// Convert protobuf Height to clienttypes.Height
	toHeight := ConvertHeightFromPbToDb(req.ToHeight)

	// Get SHFU records from storage by height
	records, err := srv.storage.FindSHFUByChainAndHeight(ctx, req.ChainId, req.CounterpartyChainId, toHeight)
	if err != nil {
		logger.ErrorContext(ctx, "GetSHFUByHeight request failed", err,
			"request_id", req.RequestId,
			"chain_id", req.ChainId,
			"counterparty_chain_id", req.CounterpartyChainId,
			"to_height", fmt.Sprintf("%d-%d", req.ToHeight.RevisionNumber, req.ToHeight.RevisionHeight))
		return nil, fmt.Errorf("failed to get SHFU by height: %w", err)
	}

	if len(records) == 0 {
		logger.InfoContext(ctx, "GetSHFUByHeight request completed - no records found",
			"request_id", req.RequestId,
			"chain_id", req.ChainId,
			"counterparty_chain_id", req.CounterpartyChainId,
			"to_height", fmt.Sprintf("%d-%d", req.ToHeight.RevisionNumber, req.ToHeight.RevisionHeight),
			"found", false)
		return &GetSHFUByHeightResponse{Found: false}, nil
	}

	// Return the first matching record (there should typically be only one)
	record := records[0]

	// Convert to protobuf message
	pbRecord := ConvertSHFURecordFromDbToPb(record)

	logger.InfoContext(ctx, "GetSHFUByHeight request completed successfully",
		"request_id", req.RequestId,
		"chain_id", req.ChainId,
		"counterparty_chain_id", req.CounterpartyChainId,
		"to_height", fmt.Sprintf("%d-%d", req.ToHeight.RevisionNumber, req.ToHeight.RevisionHeight),
		"found", true,
		"records_count", len(records))

	return &GetSHFUByHeightResponse{Found: true, Record: pbRecord}, nil
}
