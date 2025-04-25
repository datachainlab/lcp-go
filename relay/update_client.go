package relay

import (
	"context"
	"fmt"
	"github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/datachainlab/lcp-go/relay/elc"
)

func updateClient(ctx context.Context, chunkSize uint32, client LCPServiceClient, anyHeader *types.Any, elcClientID string, includeState bool, signer []byte) (*elc.MsgUpdateClientResponse, error) {
	stream, err := client.UpdateClientStream(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to call UpdateClientStream: %w", err)
	}
	if err = stream.Send(&elc.MsgUpdateClientStreamChunk{
		Chunk: &elc.MsgUpdateClientStreamChunk_Init{
			Init: &elc.UpdateClientStreamInit{
				ClientId:     elcClientID,
				IncludeState: includeState,
				Signer:       signer,
				TypeUrl:      anyHeader.TypeUrl,
			},
		},
	}); err != nil {
		return nil, fmt.Errorf("failed to send initial message: %w", err)
	}
	chunks, err := splitBytes(anyHeader.Value, chunkSize)
	if err != nil {
		return nil, fmt.Errorf("failed to call splitBytes: %w", err)
	}
	for i, chunk := range chunks {
		err = stream.Send(&elc.MsgUpdateClientStreamChunk{
			Chunk: &elc.MsgUpdateClientStreamChunk_HeaderChunk{
				HeaderChunk: &elc.UpdateClientStreamHeaderChunk{
					Data: chunk,
				},
			},
		})
		if err != nil {
			return nil, fmt.Errorf("failed to send header chunk: index=%d, %w", i, err)
		}
	}
	return stream.CloseAndRecv()
}

func splitBytes(data []byte, size uint32) ([][]byte, error) {
	if size == 0 {
		return nil, fmt.Errorf("chunk size must be greater than 0")
	}
	var chunks [][]byte
	for i := 0; i < len(data); i += int(size) {
		end := i + int(size)
		if end > len(data) {
			end = len(data)
		}
		chunks = append(chunks, data[i:end])
	}
	return chunks, nil
}
