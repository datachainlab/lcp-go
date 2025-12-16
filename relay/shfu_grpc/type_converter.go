package shfu_grpc

import (
	clienttypes "github.com/cosmos/ibc-go/v8/modules/core/02-client/types"
	"github.com/cosmos/ibc-go/v8/modules/core/exported"
	"github.com/datachainlab/lcp-go/relay/shfu_storage"
)

// ConvertSHFURecordFromDbToPb converts storage.SHFURecord to protobuf SHFURecord
func ConvertSHFURecordFromDbToPb(record *shfu_storage.SHFURecord) *SHFURecord {
	if record == nil {
		return nil
	}

	return &SHFURecord{
		ChainId:               record.ChainID,
		CounterpartyChainId:   record.CounterpartyChainID,
		FromHeight:            ConvertHeightFromDbToPb(record.FromHeight),
		ToHeight:              ConvertHeightFromDbToPb(record.ToHeight),
		UpdatedAt:             record.UpdatedAt,
		UpdateClientResults:   ConvertUpdateClientResultsFromDbToPb(record.UpdateClientResults),
		LatestFinalizedHeader: record.LatestFinalizedHeader,
	}
}

// ConvertSHFURecordFromPbToDb converts protobuf SHFURecord to storage.SHFURecord
func ConvertSHFURecordFromPbToDb(pbRecord *SHFURecord) *shfu_storage.SHFURecord {
	if pbRecord == nil {
		return nil
	}

	return &shfu_storage.SHFURecord{
		ChainID:               pbRecord.ChainId,
		CounterpartyChainID:   pbRecord.CounterpartyChainId,
		FromHeight:            ConvertHeightFromPbToDb(pbRecord.FromHeight),
		ToHeight:              ConvertHeightFromPbToDb(pbRecord.ToHeight),
		UpdatedAt:             pbRecord.UpdatedAt,
		UpdateClientResults:   ConvertUpdateClientResultsFromPbToDb(pbRecord.UpdateClientResults),
		LatestFinalizedHeader: pbRecord.LatestFinalizedHeader,
	}
}

// ConvertHeightFromDbToPb converts clienttypes.Height to protobuf Height
func ConvertHeightFromDbToPb(height clienttypes.Height) *Height {
	return &Height{
		RevisionNumber: height.GetRevisionNumber(),
		RevisionHeight: height.GetRevisionHeight(),
	}
}

// ConvertHeightFromIbcToPb converts exported.Height to protobuf Height
func ConvertHeightFromIbcToPb(height exported.Height) *Height {
	return &Height{
		RevisionNumber: height.GetRevisionNumber(),
		RevisionHeight: height.GetRevisionHeight(),
	}
}

// ConvertHeightFromPbToDb converts protobuf Height to clienttypes.Height
func ConvertHeightFromPbToDb(pbHeight *Height) clienttypes.Height {
	if pbHeight == nil {
		return clienttypes.Height{}
	}

	return clienttypes.Height{
		RevisionNumber: pbHeight.RevisionNumber,
		RevisionHeight: pbHeight.RevisionHeight,
	}
}

// ConvertUpdateClientResultsFromDbToPb converts storage UpdateClientResults to protobuf format
func ConvertUpdateClientResultsFromDbToPb(results []*shfu_storage.UpdateClientResult) []*UpdateClientResult {
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

// ConvertUpdateClientResultsFromPbToDb converts protobuf UpdateClientResults to storage format
func ConvertUpdateClientResultsFromPbToDb(pbResults []*UpdateClientResult) []*shfu_storage.UpdateClientResult {
	if pbResults == nil {
		return nil
	}

	results := make([]*shfu_storage.UpdateClientResult, len(pbResults))
	for i, pbResult := range pbResults {
		results[i] = &shfu_storage.UpdateClientResult{
			Message:   pbResult.Message,
			Signature: pbResult.Signature,
		}
	}
	return results
}
