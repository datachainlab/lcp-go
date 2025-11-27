package shfu_grpc

import (
	"context"
	"fmt"

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
	// Get latest SHFU record from storage
	record, err := srv.storage.GetLatestSHFUForChain(ctx, req.ChainId, req.CounterpartyChainId)
	if err != nil {
		return nil, fmt.Errorf("failed to get latest SHFU: %w", err)
	}

	if record == nil {
		return &GetLatestSHFUResponse{Found: false}, nil
	}

	// Convert to protobuf message
	pbRecord := ConvertSHFURecordFromDbToPb(record)

	return &GetLatestSHFUResponse{Found: true, Record: pbRecord}, nil
}

// GetSHFUByHeight implements the gRPC service method to get SHFU record by height range
func (srv *SHFUGRPCServer) GetSHFUByHeight(ctx context.Context, req *GetSHFUByHeightRequest) (*GetSHFUByHeightResponse, error) {
	// Convert protobuf Height to clienttypes.Height
	toHeight := ConvertHeightFromPbToDb(req.ToHeight)

	// Get SHFU records from storage by height
	records, err := srv.storage.FindSHFUByChainAndHeight(ctx, req.ChainId, req.CounterpartyChainId, toHeight)
	if err != nil {
		return nil, fmt.Errorf("failed to get SHFU by height: %w", err)
	}

	if len(records) == 0 {
		return &GetSHFUByHeightResponse{Found: false}, nil
	}

	// Return the first matching record (there should typically be only one)
	record := records[0]

	// Convert to protobuf message
	pbRecord := ConvertSHFURecordFromDbToPb(record)

	return &GetSHFUByHeightResponse{Found: true, Record: pbRecord}, nil
}
