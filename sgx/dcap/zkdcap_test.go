package dcap

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseDCAPVerifierCommit_SWHardeningNeeded(t *testing.T) {
	input, err := hex.DecodeString("0000000300000000050000001200906ed50000a1acc73eb45794fa1734f14d882e91925b6006f79d3bb2460df9d01b333d70090000000067b3f1fa0000000067db736115150b07ff800e00000000000000000000000000000000000000000000000000000000000000000000000000000000000500000000000000070000000000000026ae825ffce1cf9dcdf682614f4d36704e7bca087bbb5264aca9301d7824cec8000000000000000000000000000000000000000000000000000000000000000083d719e77deaca1470f6baf62a4d774303c899db69020f9c70ee1dfc08c7ce9e0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001c170f98628b3a01b15654fbfaad1aaf3419b2c3c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000000e494e54454c2d53412d3030333334000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000e494e54454c2d53412d3030363135000000000000000000000000000000000000")
	require.NoError(t, err)
	commit, err := ParseQuoteVerificationOutput(input)
	require.NoError(t, err)
	require.EqualValues(t, 0, commit.Version)
	require.EqualValues(t, 3, commit.QuoteVersion)
	require.EqualValues(t, 0, commit.TeeType)
	require.EqualValues(t, SWHardeningNeeded, commit.TcbStatus)
	require.EqualValues(t, []byte{0, 144, 110, 213, 0, 0}, commit.Fmspc)
	expectedMrEnclave, _ := hex.DecodeString("26ae825ffce1cf9dcdf682614f4d36704e7bca087bbb5264aca9301d7824cec8")
	require.EqualValues(t, expectedMrEnclave, commit.QuoteBody.AsEnclaveIdentity().MrEnclave)
	reportData, _ := hex.DecodeString("01c170f98628b3a01b15654fbfaad1aaf3419b2c3c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
	require.EqualValues(t, reportData, commit.ReportData(), hex.EncodeToString(commit.ReportData()))
	require.Len(t, commit.AdvisoryIds, 2)
	require.EqualValues(t, []string{"INTEL-SA-00334", "INTEL-SA-00615"}, commit.AdvisoryIds)
	require.EqualValues(t, commit.SGXIntelRootCAHash, HashTrustRootCert())

	require.EqualValues(t, input, commit.ToBytes())
}

func TestParseDCAPVerifierCommit_Simulation_UpToDate(t *testing.T) {
	input, err := hex.DecodeString("0000000300000000000000000000606a000000d61f4e3d30011899d16131d4c940ef1f75ec53d7f9a70cbb3aab1f5ab0235b2b000000000000000100000000ffffffff4820f3376ae6b2f2034d3b7a4b48a7780000000000000000000000000000000000000000000000000000000000000000070000000000000007000000000000003a354bf808b89267b19c6b390ee484d1bee8d301d0058fac511a900d5d0a6f68000000000000000000000000000000000000000000000000000000000000000083d719e77deaca1470f6baf62a4d774303c899db69020f9c70ee1dfc08c7ce9e00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000019c69756b02dd84ad5d7a11758025ae4a7edf938d0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000")
	require.NoError(t, err)
	commit, err := ParseQuoteVerificationOutput(input)
	require.NoError(t, err)
	require.EqualValues(t, 0, commit.Version)
	require.EqualValues(t, 3, commit.QuoteVersion)
	require.EqualValues(t, 0, commit.TeeType)
	require.EqualValues(t, UpToDate, commit.TcbStatus)
	require.EqualValues(t, []byte{0, 96, 106, 0, 0, 0}, commit.Fmspc)
	expectedMrEnclave, _ := hex.DecodeString("3a354bf808b89267b19c6b390ee484d1bee8d301d0058fac511a900d5d0a6f68")
	require.EqualValues(t, expectedMrEnclave, commit.QuoteBody.AsEnclaveIdentity().MrEnclave)
	reportData, _ := hex.DecodeString("019c69756b02dd84ad5d7a11758025ae4a7edf938d00000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
	require.EqualValues(t, reportData, commit.ReportData(), hex.EncodeToString(commit.ReportData()))
	require.Len(t, commit.AdvisoryIds, 0)
	require.EqualValues(t, commit.SGXIntelRootCAHash, [32]byte{
		214, 31, 78, 61, 48, 1, 24, 153, 209, 97, 49, 212, 201, 64, 239, 31, 117, 236, 83, 215, 249,
		167, 12, 187, 58, 171, 31, 90, 176, 35, 91, 43,
	})
	require.EqualValues(t, input, commit.ToBytes())
}
