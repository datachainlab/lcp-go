package shfu_grpc

import (
	"context"
	"fmt"
	"strings"

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

// GetSequentialSHFURecords implements the gRPC service method to get sequential SHFU records
func (srv *SHFUGRPCServer) GetSequentialSHFURecords(ctx context.Context, req *GetSequentialSHFURecordsRequest) (*GetSequentialSHFURecordsResponse, error) {
	logger := shfu_logger.GetSHFULogger(ctx)

	logger.InfoContext(ctx, "GetSequentialSHFURecords request started",
		"request_id", req.RequestId,
		"chain_id", req.ChainId,
		"counterparty_chain_id", req.CounterpartyChainId,
		"from_height", fmt.Sprintf("%d-%d", req.FromHeight.RevisionNumber, req.FromHeight.RevisionHeight))

	// Convert protobuf Height to clienttypes.Height
	fromHeight := ConvertHeightFromPbToDb(req.FromHeight)
	toHeight := ConvertHeightFromPbToDb(req.ToHeight)

	// Get sequential SHFU records from storage (no toHeight limit for gRPC calls)
	records, err := srv.storage.GetSequentialSHFURecords(ctx, req.ChainId, req.CounterpartyChainId, fromHeight, toHeight)
	if err != nil {
		logger.ErrorContext(ctx, "GetSequentialSHFURecords request failed", err,
			"request_id", req.RequestId,
			"chain_id", req.ChainId,
			"counterparty_chain_id", req.CounterpartyChainId,
			"from_height", fmt.Sprintf("%d-%d", req.FromHeight.RevisionNumber, req.FromHeight.RevisionHeight))
		return nil, fmt.Errorf("failed to get sequential SHFU records: %w", err)
	}

	// Convert records to protobuf messages
	var pbRecords []*SHFURecord
	for _, record := range records {
		pbRecords = append(pbRecords, ConvertSHFURecordFromDbToPb(record))
	}

	var heights []string
	for _, record := range records {
		heights = append(heights, fmt.Sprintf("%d-%d..%d-%d", record.FromHeight.RevisionNumber, record.FromHeight.RevisionHeight, record.ToHeight.RevisionNumber, record.ToHeight.RevisionHeight))
	}
	logger.InfoContext(ctx, "GetSequentialSHFURecords request completed successfully",
		"request_id", req.RequestId,
		"chain_id", req.ChainId,
		"counterparty_chain_id", req.CounterpartyChainId,
		"from_height", fmt.Sprintf("%d-%d", req.FromHeight.RevisionNumber, req.FromHeight.RevisionHeight),
		"records_count", len(records),
		"heights", strings.Join(heights, ","),
	)

	return &GetSequentialSHFURecordsResponse{
		Records:      pbRecords,
		RecordsCount: int32(len(records)),
	}, nil
}

// GetLatestSHFU implements the gRPC service method to get the latest SHFU record
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
		"record_from_height", fmt.Sprintf("%d-%d", record.FromHeight.RevisionNumber, record.FromHeight.RevisionHeight),
		"record_to_height", fmt.Sprintf("%d-%d", record.ToHeight.RevisionNumber, record.ToHeight.RevisionHeight))

	return &GetLatestSHFUResponse{Found: true, Record: pbRecord}, nil
}
