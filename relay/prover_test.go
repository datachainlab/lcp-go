package relay

import (
	"context"
	"fmt"
	"testing"

	"github.com/datachainlab/lcp-go/relay/elc"
	"github.com/hyperledger-labs/yui-relayer/log"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

func TestSplitMessagesBySigner(t *testing.T) {
	var M = func(n uint8) []byte {
		return []byte(fmt.Sprintf("message-%03d", n))
	}
	var S = func(n uint8) []byte {
		return []byte(fmt.Sprintf("signature-%03d", n))
	}
	var Signer = func(n uint8) []byte {
		return []byte(fmt.Sprintf("signer-%03d", n))
	}
	var cases = []struct {
		Messages   [][]byte
		Signatures [][]byte
		BatchSizes []int
		Signers    [][]byte
		Error      bool
	}{
		{
			Messages:   [][]byte{M(0), M(1), M(2), M(3), M(4)},
			Signatures: [][]byte{S(0), S(1), S(2), S(3), S(4)},
			BatchSizes: []int{5},
			Signers:    [][]byte{Signer(0), Signer(0), Signer(0), Signer(0), Signer(0)},
			Error:      false,
		},
		{
			Messages:   [][]byte{M(0), M(1), M(2), M(3), M(4)},
			Signatures: [][]byte{S(0), S(1), S(2), S(3), S(4)},
			BatchSizes: []int{2, 1, 2},
			Signers:    [][]byte{Signer(0), Signer(0), Signer(1), Signer(2), Signer(2)},
			Error:      false,
		},
	}
	for i, c := range cases {
		t.Run(fmt.Sprintf("case-%d", i), func(t *testing.T) {
			require := require.New(t)
			signerMessages, err := splitMessagesBySigner(c.Messages, c.Signatures, c.Signers)
			if c.Error {
				require.Error(err)
				return
			} else {
				require.NoError(err)
			}
			require.Len(signerMessages, len(signerMessages))
			messageIndex := 0
			for i, size := range c.BatchSizes {
				require.Equal(signerMessages[i].Signer, c.Signers[messageIndex])
				require.Len(signerMessages[i].Messages, size)
				require.Len(signerMessages[i].Signatures, size)
				messageIndex += size
			}
		})
	}
}

func TestSplitIntoMultiBatch(t *testing.T) {
	var M = func(n uint8) []byte {
		return []byte(fmt.Sprintf("message-%03d", n))
	}
	var S = func(n uint8) []byte {
		return []byte(fmt.Sprintf("signature-%03d", n))
	}
	var Signer = func(n uint8) []byte {
		return []byte(fmt.Sprintf("signer-%03d", n))
	}
	var cases = []struct {
		Messages         [][]byte
		Signatures       [][]byte
		BatchSizes       []int
		Signer           []byte
		MessageBatchSize uint64
		Error            bool
	}{
		// Messages.len = 1 is invalid
		{
			Messages:         [][]byte{M(0)},
			Signatures:       [][]byte{S(0)},
			BatchSizes:       []int{1},
			Signer:           Signer(0),
			MessageBatchSize: 1,
			Error:            true,
		},
		{
			Messages:         [][]byte{M(0), M(1)},
			Signatures:       [][]byte{S(0), S(1)},
			BatchSizes:       []int{2},
			Signer:           Signer(0),
			MessageBatchSize: 2,
			Error:            false,
		},
		{
			Messages:         [][]byte{M(0), M(1), M(2)},
			Signatures:       [][]byte{S(0), S(1), S(2)},
			BatchSizes:       []int{3},
			Signer:           Signer(0),
			MessageBatchSize: 3,
			Error:            false,
		},
		{
			Messages:         [][]byte{M(0), M(1), M(2)},
			Signatures:       [][]byte{S(0), S(1), S(2)},
			BatchSizes:       []int{2, 1},
			Signer:           Signer(0),
			MessageBatchSize: 2,
			Error:            false,
		},
		{
			Messages:         [][]byte{M(0), M(1), M(2), M(3)},
			Signatures:       [][]byte{S(0), S(1), S(2), S(3)},
			BatchSizes:       []int{3, 1},
			Signer:           Signer(0),
			MessageBatchSize: 3,
			Error:            false,
		},
		{
			Messages:         [][]byte{M(0), M(1), M(2), M(3), M(4)},
			Signatures:       [][]byte{S(0), S(1), S(2), S(3), S(4)},
			BatchSizes:       []int{3, 2},
			Signer:           Signer(0),
			MessageBatchSize: 3,
			Error:            false,
		},
	}
	for i, c := range cases {
		t.Run(fmt.Sprintf("case-%d", i), func(t *testing.T) {
			require := require.New(t)
			batches, err := splitIntoMultiBatch(c.Messages, c.Signatures, c.Signer, c.MessageBatchSize)
			if c.Error {
				require.Error(err)
				return
			} else {
				require.NoError(err)
			}
			require.Len(batches, len(c.BatchSizes))
			for i, size := range c.BatchSizes {
				require.Equal(batches[i].Signer, c.Signer)
				require.Len(batches[i].Messages, size)
				require.Len(batches[i].Signatures, size)
			}
		})
	}
}

func TestAggregateMessages(t *testing.T) {
	var M = func(n uint8) []byte {
		return []byte(fmt.Sprintf("message-%03d", n))
	}
	var S = func(n uint8) []byte {
		return []byte(fmt.Sprintf("signature-%03d", n))
	}
	var Signer = func(n uint8) []byte {
		return []byte(fmt.Sprintf("signer-%03d", n))
	}

	err := log.InitLogger("DEBUG", "text", "stdout", false)
	require.NoError(t, err)
	logger := log.GetLogger()

	var cases = []struct {
		Messages   [][]byte
		Signatures [][]byte
		Signer     []byte
		BatchSize  uint64
		Error      bool
	}{
		// Messages.len = 0 is invalid
		{
			Messages:   [][]byte{},
			Signatures: [][]byte{},
			Signer:     Signer(0),
			BatchSize:  2,
			Error:      true,
		},
		{
			Messages:   [][]byte{M(0)},
			Signatures: [][]byte{S(0)},
			Signer:     Signer(0),
			BatchSize:  2,
			Error:      false,
		},
		{
			Messages:   [][]byte{M(0), M(1)},
			Signatures: [][]byte{S(0), S(1)},
			Signer:     Signer(0),
			BatchSize:  2,
			Error:      false,
		},
		// BatchSize = 1 is invalid
		{
			Messages:   [][]byte{M(0), M(1)},
			Signatures: [][]byte{S(0), S(1)},
			Signer:     Signer(0),
			BatchSize:  1,
			Error:      true,
		},
		{
			Messages:   [][]byte{M(0), M(1), M(2)},
			Signatures: [][]byte{S(0), S(1), S(2)},
			Signer:     Signer(0),
			BatchSize:  2,
			Error:      false,
		},
		{
			Messages:   [][]byte{M(0), M(1), M(2), M(3)},
			Signatures: [][]byte{S(0), S(1), S(2), S(3)},
			Signer:     Signer(0),
			BatchSize:  2,
			Error:      false,
		},
		{
			Messages:   [][]byte{M(0), M(1), M(2), M(3), M(4)},
			Signatures: [][]byte{S(0), S(1), S(2), S(3), S(4)},
			Signer:     Signer(0),
			BatchSize:  2,
			Error:      false,
		},
	}

	for i, c := range cases {
		t.Run(fmt.Sprintf("case-%d", i), func(t *testing.T) {
			require := require.New(t)
			res, err := aggregateMessages(context.Background(), logger, c.BatchSize, mockMessageAggregator, c.Messages, c.Signatures, c.Signer)
			if c.Error {
				require.Error(err)
				return
			} else {
				require.NoError(err)
			}
			require.Equal(res.ProxyMessage, concatBytes(c.Messages))
			require.Equal(res.Signatures[0], concatBytes(c.Signatures))
		})
	}
}

func concatBytes(bzs [][]byte) []byte {
	var res []byte
	for _, b := range bzs {
		res = append(res, b...)
	}
	return res
}

func mockMessageAggregator(_ context.Context, in *elc.MsgAggregateMessages, _ ...grpc.CallOption) (*elc.MsgAggregateMessagesResponse, error) {
	var res elc.MsgAggregateMessagesResponse
	if len(in.Messages) != len(in.Signatures) {
		return nil, fmt.Errorf("messages and signatures must have the same length")
	}
	if len(in.Messages) == 0 {
		return nil, fmt.Errorf("messages.len = 0 is invalid")
	} else if len(in.Messages) == 1 {
		return nil, fmt.Errorf("messages.len = 1 is invalid")
	}
	for i := 0; i < len(in.Messages); i++ {
		res.Message = append(res.Message, in.Messages[i]...)
		res.Signature = append(res.Signature, in.Signatures[i]...)
	}
	return &res, nil
}
