package raw

import (
	"encoding/hex"
	fmt "fmt"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/hyperledger-labs/yui-relayer/signer"
)

var _ signer.SignerConfig = (*SignerConfig)(nil)

func (c *SignerConfig) Validate() error {
	if _, err := hex.DecodeString(strings.TrimPrefix(c.PrivateKey, "0x")); err != nil {
		return fmt.Errorf("invalid private key: %w", err)
	}
	return nil
}

func (c *SignerConfig) Build() (signer.Signer, error) {
	bz, err := hex.DecodeString(strings.TrimPrefix(c.PrivateKey, "0x"))
	if err != nil {
		return nil, fmt.Errorf("failed to decode private key: %w", err)
	}
	privKey, err := crypto.ToECDSA(bz)
	if err != nil {
		return nil, fmt.Errorf("failed to decode to ECDSA: %w", err)
	}
	return NewSigner(privKey), nil
}
