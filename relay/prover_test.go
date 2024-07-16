package relay

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSplitIntoMultiBatch(t *testing.T) {
	var M = func(n uint64) []byte {
		return []byte(fmt.Sprintf("message-%d", n))
	}
	var S = func(n uint64) []byte {
		return []byte(fmt.Sprintf("signature-%d", n))
	}
	var Signer = func(n uint64) []byte {
		return []byte(fmt.Sprintf("signer-%d", n))
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
