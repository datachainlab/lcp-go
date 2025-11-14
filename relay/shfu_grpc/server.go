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
	pbRecord := &SHFURecord{
		ChainId:               record.ChainID,
		CounterpartyChainId:   record.CounterpartyChainID,
		FromHeight:            &Height{RevisionNumber: record.FromHeight.GetRevisionNumber(), RevisionHeight: record.FromHeight.GetRevisionHeight()},
		ToHeight:              &Height{RevisionNumber: record.ToHeight.GetRevisionNumber(), RevisionHeight: record.ToHeight.GetRevisionHeight()},
		ToHeightTime:          record.ToHeightTime,
		UpdatedAt:             record.UpdatedAt,
		UpdateClientResults:   convertUpdateClientResults(record.UpdateClientResults),
		LatestFinalizedHeader: record.LatestFinalizedHeader,
	}

	return &GetLatestSHFUResponse{Found: true, Record: pbRecord}, nil
}

// convertUpdateClientResults converts storage UpdateClientResults to protobuf format
func convertUpdateClientResults(results []*shfu_storage.UpdateClientResult) []*UpdateClientResult {
	if results == nil {
		return nil
	}

	pbResults := make([]*UpdateClientResult, len(results))
	for i, result := range results {
		pbResults[i] = &UpdateClientResult{
			Message:   result.Message,
			Signature: result.Signature,
		}
	}
	return pbResults
}
