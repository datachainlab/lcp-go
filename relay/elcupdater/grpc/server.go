package grpc

import (
	"context"
	"fmt"
	"strings"

	elc_updater_logger "github.com/datachainlab/lcp-go/relay/elcupdater/logger"
	elc_updater_storage "github.com/datachainlab/lcp-go/relay/elcupdater/storage"
	"github.com/hyperledger-labs/yui-relayer/log"
)

// ELCUpdaterGRPCServer implements the gRPC ELCUpdaterServer interface
type ELCUpdaterServiceGRPCServer struct {
	storage elc_updater_storage.ELCUpdateStorage
	UnimplementedELCUpdaterServiceServer
}

// NewELCUpdaterServiceGRPCServer creates a new ELCUpdaterServiceGRPCServer
func NewELCUpdaterServiceGRPCServer(storage elc_updater_storage.ELCUpdateStorage) *ELCUpdaterServiceGRPCServer {
	return &ELCUpdaterServiceGRPCServer{
		UnimplementedELCUpdaterServiceServer: UnimplementedELCUpdaterServiceServer{},
		storage:                              storage,
	}
}

// GetSequentialELCUpdateRecords implements the gRPC service method to get sequential ELC update records
func (srv *ELCUpdaterServiceGRPCServer) GetSequentialRecords(ctx context.Context, req *GetSequentialRecordsRequest) (*GetSequentialRecordsResponse, error) {
	logger := log.RelayLogger{
		Logger: elc_updater_logger.GetELCUpdaterLogger(ctx).With(
			"function", "GetSequentialRecords",
			"request_id", req.RequestId,
			"chain_id", req.ChainId,
			"counterparty_chain_id", req.CounterpartyChainId,
			"from_height", fmt.Sprintf("%d-%d", req.FromHeight.RevisionNumber, req.FromHeight.RevisionHeight),
		),
	}
	logger.InfoContext(ctx, "GetSequentialRecords request started")

	// Convert protobuf Height to clienttypes.Height
	fromHeight := ConvertHeightFromPbToDb(req.FromHeight)
	toHeight := ConvertHeightFromPbToDb(req.ToHeight)

	// Get sequential ELCUpdateRecords from storage (no toHeight limit for gRPC calls)
	records, err := srv.storage.GetSequence(ctx, req.ChainId, req.CounterpartyChainId, fromHeight, toHeight)
	if err != nil {
		logger.ErrorContext(ctx, "GetSequence request failed", err)
		return nil, fmt.Errorf("failed to get GetSequence: %w", err)
	}

	// Convert records to protobuf messages
	var pbRecords []*ELCUpdateRecord
	for _, record := range records {
		pbRecords = append(pbRecords, ConvertELCUpdateRecordFromDbToPb(record))
	}

	var heights []string
	for _, record := range records {
		heights = append(heights, fmt.Sprintf("%d-%d..%d-%d", record.FromHeight.RevisionNumber, record.FromHeight.RevisionHeight, record.ToHeight.RevisionNumber, record.ToHeight.RevisionHeight))
	}
	logger.InfoContext(ctx, "GetSequence request completed successfully",
		"records_count", len(records),
		"heights", strings.Join(heights, ","),
	)

	return &GetSequentialRecordsResponse{
		Records:      pbRecords,
		RecordsCount: int32(len(records)),
	}, nil
}

// GetLatestELCUpdateRecord implements the gRPC service method to get the latest ELC update record
func (srv *ELCUpdaterServiceGRPCServer) GetLatestRecord(ctx context.Context, req *GetLatestRecordRequest) (*GetLatestRecordResponse, error) {
	logger := log.RelayLogger{
		Logger: elc_updater_logger.GetELCUpdaterLogger(ctx).With(
			"function", "GetLatestRecord",
			"request_id", req.RequestId,
			"chain_id", req.ChainId,
			"counterparty_chain_id", req.CounterpartyChainId,
		),
	}
	logger.InfoContext(ctx, "GetLatestRecord request started")

	// Get latest ELC update record from storage
	record, err := srv.storage.GetLatestForChain(ctx, req.ChainId, req.CounterpartyChainId)
	if err != nil {
		logger.ErrorContext(ctx, "GetLatestForChain request failed", err)
		return nil, fmt.Errorf("failed to GetLatestForChain: %w", err)
	}

	if record == nil {
		logger.InfoContext(ctx, "GetLatestForChain request completed - no record found",
			"found", false)
		return &GetLatestRecordResponse{Found: false}, nil
	}

	// Convert to protobuf message
	pbRecord := ConvertELCUpdateRecordFromDbToPb(record)
	logger.InfoContext(ctx, "GetLatestForChain request completed successfully",
		"found", true,
		"record_from_height", fmt.Sprintf("%d-%d", record.FromHeight.RevisionNumber, record.FromHeight.RevisionHeight),
		"record_to_height", fmt.Sprintf("%d-%d", record.ToHeight.RevisionNumber, record.ToHeight.RevisionHeight))

	return &GetLatestRecordResponse{Found: true, Record: pbRecord}, nil
}
