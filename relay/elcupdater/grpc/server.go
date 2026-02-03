package grpc

import (
	"context"
	"fmt"
	"strings"

	elcupdater_log "github.com/datachainlab/lcp-go/relay/elcupdater/log"
	"github.com/datachainlab/lcp-go/relay/elcupdater/storage"
	"github.com/hyperledger-labs/yui-relayer/log"
)

// Server implements the gRPC Server interface
type Server struct {
	storage storage.Storage
	UnimplementedServiceServer
}

// NewServer creates a new Server
func NewServer(sto storage.Storage) *Server {
	return &Server{
		UnimplementedServiceServer: UnimplementedServiceServer{},
		storage:                    sto,
	}
}

// GetSequentialRecords implements the gRPC service method to get sequential ELC update records
func (srv *Server) GetSequentialRecords(ctx context.Context, req *GetSequentialRecordsRequest) (*GetSequentialRecordsResponse, error) {
	logger := log.RelayLogger{
		Logger: elcupdater_log.GetLogger(ctx).With(
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

	// Get sequential records from storage (no toHeight limit for gRPC calls)
	records, err := srv.storage.GetSequential(ctx, req.ChainId, req.CounterpartyChainId, fromHeight, toHeight)
	if err != nil {
		logger.ErrorContext(ctx, "GetSequential request failed", err)
		return nil, fmt.Errorf("failed to get GetSequential: %w", err)
	}

	// Convert records to protobuf messages
	var pbRecords []*Record
	for _, record := range records {
		pbRecords = append(pbRecords, ConvertRecordFromDbToPb(record))
	}

	var heights []string
	for _, record := range records {
		heights = append(heights, fmt.Sprintf("%d-%d..%d-%d", record.FromHeight.RevisionNumber, record.FromHeight.RevisionHeight, record.ToHeight.RevisionNumber, record.ToHeight.RevisionHeight))
	}
	logger.InfoContext(ctx, "GetSequential request completed successfully",
		"records_count", len(records),
		"heights", strings.Join(heights, ","),
	)

	return &GetSequentialRecordsResponse{
		Records:      pbRecords,
		RecordsCount: int32(len(records)),
	}, nil
}

// GetLatestRecord implements the gRPC service method to get the latest record
func (srv *Server) GetLatestRecord(ctx context.Context, req *GetLatestRecordRequest) (*GetLatestRecordResponse, error) {
	logger := log.RelayLogger{
		Logger: elcupdater_log.GetLogger(ctx).With(
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
	pbRecord := ConvertRecordFromDbToPb(record)
	logger.InfoContext(ctx, "GetLatestForChain request completed successfully",
		"found", true,
		"record_from_height", fmt.Sprintf("%d-%d", record.FromHeight.RevisionNumber, record.FromHeight.RevisionHeight),
		"record_to_height", fmt.Sprintf("%d-%d", record.ToHeight.RevisionNumber, record.ToHeight.RevisionHeight))

	return &GetLatestRecordResponse{Found: true, Record: pbRecord}, nil
}
