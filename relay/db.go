package relay

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/datachainlab/lcp-go/relay/enclave"
	"github.com/hyperledger-labs/yui-relayer/core"
)

const (
	lastFinalizedEnclaveKeyInfoFile   = "last_finalized_eki"
	lastUnfinalizedEnclaveKeyInfoFile = "last_unfinalized_eki"
)

var ErrEnclaveKeyInfoNotFound = errors.New("enclave key info not found")

type unfinalizedEKI struct {
	Info       *enclave.EnclaveKeyInfo `json:"info"`
	MsgIDBytes []byte                  `json:"msg_id_bytes"`
}

func (pr *Prover) dbPath() string {
	return filepath.Join(pr.homePath, "lcp", pr.originChain.ChainID())
}

func (pr *Prover) lastEnclaveKeyInfoFilePath(finalized bool) string {
	if finalized {
		return filepath.Join(pr.dbPath(), lastFinalizedEnclaveKeyInfoFile)
	} else {
		return filepath.Join(pr.dbPath(), lastUnfinalizedEnclaveKeyInfoFile)
	}
}

func (pr *Prover) loadLastFinalizedEnclaveKey(ctx context.Context) (*enclave.EnclaveKeyInfo, error) {
	path := pr.lastEnclaveKeyInfoFilePath(true)
	bz, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%v not found: %w", path, ErrEnclaveKeyInfoNotFound)
		}
		return nil, err
	}
	var eki enclave.EnclaveKeyInfo
	if err := json.Unmarshal(bz, &eki); err != nil {
		return nil, err
	}
	return &eki, nil
}

func (pr *Prover) loadLastUnfinalizedEnclaveKey(ctx context.Context) (*enclave.EnclaveKeyInfo, core.MsgID, error) {
	path := pr.lastEnclaveKeyInfoFilePath(false)
	bz, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, fmt.Errorf("%v not found: %w", path, ErrEnclaveKeyInfoNotFound)
		}
		return nil, nil, err
	}
	var ueki unfinalizedEKI
	if err := json.Unmarshal(bz, &ueki); err != nil {
		return nil, nil, err
	}
	var unfinalizedMsgID core.MsgID
	if err := pr.codec.UnmarshalInterface(ueki.MsgIDBytes, &unfinalizedMsgID); err != nil {
		return nil, nil, err
	}
	return ueki.Info, unfinalizedMsgID, nil
}

func (pr *Prover) saveFinalizedEnclaveKeyInfo(ctx context.Context, eki *enclave.EnclaveKeyInfo) error {
	log.Println("save finalized enclave key info")
	bz, err := json.Marshal(eki)
	if err != nil {
		return err
	}
	return os.WriteFile(pr.lastEnclaveKeyInfoFilePath(true), bz, 0600)
}

func (pr *Prover) saveUnfinalizedEnclaveKeyInfo(ctx context.Context, eki *enclave.EnclaveKeyInfo, msgID core.MsgID) error {
	log.Println("save unfinalized enclave key info")
	msgIDBytes, err := pr.codec.MarshalInterface(msgID)
	if err != nil {
		return err
	}
	bz, err := json.Marshal(unfinalizedEKI{
		Info:       eki,
		MsgIDBytes: msgIDBytes,
	})
	if err != nil {
		return err
	}
	return os.WriteFile(pr.lastEnclaveKeyInfoFilePath(false), bz, 0600)
}

func (pr *Prover) removeFinalizedEnclaveKeyInfo(ctx context.Context) error {
	path := pr.lastEnclaveKeyInfoFilePath(true)
	log.Printf("remove finalized enclave key info: %v", path)
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	return os.Remove(path)
}

func (pr *Prover) removeUnfinalizedEnclaveKeyInfo(ctx context.Context) error {
	path := pr.lastEnclaveKeyInfoFilePath(false)
	log.Printf("remove unfinalized enclave key info: %v", path)
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	return os.Remove(path)
}
