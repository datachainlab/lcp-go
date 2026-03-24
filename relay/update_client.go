package relay

import (
	"context"
	"fmt"
	"github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/datachainlab/lcp-go/relay/elc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func updateClient(ctx context.Context, chunkSize uint32, client LCPServiceClient, anyHeader *types.Any, elcClientID string, includeState bool, signer []byte) (*elc.MsgUpdateClientResponse, error) {
	stream, err := client.UpdateClientStream(
		ctx,
		grpc.MaxCallRecvMsgSize(DefaultGRPCMaxMsgSize),
		grpc.MaxCallSendMsgSize(DefaultGRPCMaxMsgSize),
	)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to call UpdateClientStream: max_recv_msg_size=%d max_send_msg_size=%d %w",
			DefaultGRPCMaxMsgSize,
			DefaultGRPCMaxMsgSize,
			err,
		)
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
	if err := stream.CloseSend(); err != nil {
		return nil, fmt.Errorf(
			"failed to close UpdateClientStream send: header_bytes=%d chunk_size=%d chunk_count=%d max_recv_msg_size=%d max_send_msg_size=%d %w",
			len(anyHeader.Value),
			chunkSize,
			len(chunks),
			DefaultGRPCMaxMsgSize,
			DefaultGRPCMaxMsgSize,
			err,
		)
	}

	resp := new(elc.MsgUpdateClientResponse)
	if err := stream.RecvMsg(resp); err != nil {
		st, ok := status.FromError(err)
		if ok && st.Code() == codes.ResourceExhausted {
			return nil, fmt.Errorf(
				"failed to receive UpdateClientStream response: code=%s header_bytes=%d chunk_size=%d chunk_count=%d last_chunk_size=%d max_recv_msg_size=%d max_send_msg_size=%d raw=%w",
				st.Code(),
				len(anyHeader.Value),
				chunkSize,
				len(chunks),
				lastChunkSize(chunks),
				DefaultGRPCMaxMsgSize,
				DefaultGRPCMaxMsgSize,
				err,
			)
		}
		return nil, fmt.Errorf(
			"failed to receive UpdateClientStream response: header_bytes=%d chunk_size=%d chunk_count=%d last_chunk_size=%d max_recv_msg_size=%d max_send_msg_size=%d %w",
			len(anyHeader.Value),
			chunkSize,
			len(chunks),
			lastChunkSize(chunks),
			DefaultGRPCMaxMsgSize,
			DefaultGRPCMaxMsgSize,
			err,
		)
	}
	return resp, nil
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

func lastChunkSize(chunks [][]byte) int {
	if len(chunks) == 0 {
		return 0
	}
	return len(chunks[len(chunks)-1])
}
