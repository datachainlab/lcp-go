package raw

import (
	"context"
	"crypto/ecdsa"
	"fmt"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/hyperledger-labs/yui-relayer/signer"
)

var _ signer.Signer = (*Signer)(nil)

type Signer struct {
	privKey *ecdsa.PrivateKey
}

func NewSigner(privKey *ecdsa.PrivateKey) *Signer {
	return &Signer{
		privKey: privKey,
	}
}

func (s *Signer) GetPublicKey(_ context.Context) ([]byte, error) {
	return crypto.CompressPubkey(&s.privKey.PublicKey), nil
}

func (s *Signer) Sign(_ context.Context, digest []byte) ([]byte, error) {
	sig, err := crypto.Sign(digest, s.privKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign tx: %v", err)
	}

	return sig, nil
}
