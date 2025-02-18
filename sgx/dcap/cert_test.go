package dcap

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHashTrustRootCert(t *testing.T) {
	expected, _ := hex.DecodeString("a1acc73eb45794fa1734f14d882e91925b6006f79d3bb2460df9d01b333d7009")
	require.EqualValues(t, expected, HashTrustRootCert())
}
