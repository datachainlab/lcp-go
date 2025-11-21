package shfu_grpc

import (
	"context"
	"fmt"

	clienttypes "github.com/cosmos/ibc-go/v8/modules/core/02-client/types"
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
		ToHeight:              &Height{RevisionNumber: record.ToHeight.GetRevisionNumber(), RevisionHeight: record.ToHeight.GetRevisionHeight()},
		ToHeightTime:          record.ToHeightTime,
		UpdatedAt:             record.UpdatedAt,
		UpdateClientResults:   convertUpdateClientResults(record.UpdateClientResults),
		LatestFinalizedHeader: record.LatestFinalizedHeader,
	}

	return &GetLatestSHFUResponse{Found: true, Record: pbRecord}, nil
}

// GetSHFUByHeight implements the gRPC service method to get SHFU record by height range
func (srv *SHFUGRPCServer) GetSHFUByHeight(ctx context.Context, req *GetSHFUByHeightRequest) (*GetSHFUByHeightResponse, error) {
	fmt.Printf("zzz >server.GetSHFUByHeight called with req=%v\n", req)
	ret, err := srv.GetSHFUByHeight0(ctx, req)
	fmt.Printf("zzz <server.GetSHFUByHeight returning res=%v, err=%v\n", ret, err)
	return ret, err
}
func (srv *SHFUGRPCServer) GetSHFUByHeight0(ctx context.Context, req *GetSHFUByHeightRequest) (*GetSHFUByHeightResponse, error) {
	// Convert protobuf Height to clienttypes.Height
	toHeight := clienttypes.Height{
		RevisionNumber: req.ToHeight.RevisionNumber,
		RevisionHeight: req.ToHeight.RevisionHeight,
	}

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
	pbRecord := &SHFURecord{
		ChainId:               record.ChainID,
		CounterpartyChainId:   record.CounterpartyChainID,
		ToHeight:              &Height{RevisionNumber: record.ToHeight.GetRevisionNumber(), RevisionHeight: record.ToHeight.GetRevisionHeight()},
		ToHeightTime:          record.ToHeightTime,
		UpdatedAt:             record.UpdatedAt,
		UpdateClientResults:   convertUpdateClientResults(record.UpdateClientResults),
		LatestFinalizedHeader: record.LatestFinalizedHeader,
	}

	return &GetSHFUByHeightResponse{Found: true, Record: pbRecord}, nil
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
