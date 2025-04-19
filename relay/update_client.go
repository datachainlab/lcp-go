package relay

import (
	"context"
	"fmt"
	"github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/datachainlab/lcp-go/relay/elc"
)

// Max message size is 4MB.
// 0.5MB is reserved for gRPC metadata.
const chunkSize = 3.5 * 1024 * 1024

func updateClient(ctx context.Context, client LCPServiceClient, anyHeader *types.Any, elcClientID string, includeState bool, signer []byte) (*elc.MsgUpdateClientResponse, error) {
	stream, err := client.UpdateClientStream(ctx)
	if err != nil {
		return nil, err
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
		return nil, err
	}
	chunks, err := splitBytes(anyHeader.Value, chunkSize)
	if err != nil {
		return nil, err
	}
	for _, chunk := range chunks {
		err = stream.Send(&elc.MsgUpdateClientStreamChunk{
			Chunk: &elc.MsgUpdateClientStreamChunk_HeaderChunk{
				HeaderChunk: &elc.UpdateClientStreamHeaderChunk{
					Data: chunk,
				},
			},
		})
		if err != nil {
			return nil, err
		}
	}
	return stream.CloseAndRecv()
}

func splitBytes(data []byte, size uint) ([][]byte, error) {
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
