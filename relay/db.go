package relay

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

func (pr *Prover) loadLastFinalizedEnclaveKey(context.Context) (*enclave.EnclaveKeyInfo, error) {
	path := pr.lastEnclaveKeyInfoFilePath(true)
	bz, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%v not found: %w", path, ErrEnclaveKeyInfoNotFound)
		}
		return nil, fmt.Errorf("failed to stat file: path=%v %w", path, err)
	}
	var eki enclave.EnclaveKeyInfo
	if err := json.Unmarshal(bz, &eki); err != nil {
		return nil, fmt.Errorf("failed to unmarshal enclave key info: path=%v %w", path, err)
	}
	return &eki, nil
}

func (pr *Prover) loadLastUnfinalizedEnclaveKey(context.Context) (*enclave.EnclaveKeyInfo, core.MsgID, error) {
	path := pr.lastEnclaveKeyInfoFilePath(false)
	bz, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, fmt.Errorf("%v not found: %w", path, ErrEnclaveKeyInfoNotFound)
		}
		return nil, nil, fmt.Errorf("failed to stat file: path=%v %w", path, err)
	}
	var ueki unfinalizedEKI
	if err := json.Unmarshal(bz, &ueki); err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal unfinalized enclave key info: %w", err)
	}
	var unfinalizedMsgID core.MsgID
	if err := pr.codec.UnmarshalInterface(ueki.MsgIDBytes, &unfinalizedMsgID); err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal msg id: value=%x %w", ueki.MsgIDBytes, err)
	}
	return ueki.Info, unfinalizedMsgID, nil
}

func (pr *Prover) saveFinalizedEnclaveKeyInfo(ctx context.Context, eki *enclave.EnclaveKeyInfo) error {
	pr.getLogger().InfoContext(ctx, "save finalized enclave key info")
	bz, err := json.Marshal(eki)
	if err != nil {
		return fmt.Errorf("failed to marshal enclave key info: %w", err)
	}
	if err := os.WriteFile(pr.lastEnclaveKeyInfoFilePath(true), bz, 0600); err != nil {
		return fmt.Errorf("failed to write enclave key info: %w", err)
	}
	return nil
}

func (pr *Prover) saveUnfinalizedEnclaveKeyInfo(ctx context.Context, eki *enclave.EnclaveKeyInfo, msgID core.MsgID) error {
	pr.getLogger().InfoContext(ctx, "save unfinalized enclave key info")
	msgIDBytes, err := pr.codec.MarshalInterface(msgID)
	if err != nil {
		return fmt.Errorf("failed to marshal msg id: %w", err)
	}
	bz, err := json.Marshal(unfinalizedEKI{
		Info:       eki,
		MsgIDBytes: msgIDBytes,
	})
	if err != nil {
		return fmt.Errorf("failed to marshal enclave key info: %w", err)
	}
	if err := os.WriteFile(pr.lastEnclaveKeyInfoFilePath(false), bz, 0600); err != nil {
		return fmt.Errorf("failed to write enclave key info: %w", err)
	}
	return nil
}

func (pr *Prover) removeFinalizedEnclaveKeyInfo(ctx context.Context) error {
	path := pr.lastEnclaveKeyInfoFilePath(true)
	pr.getLogger().InfoContext(ctx, "remove finalized enclave key info", "path", path)
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to stat file: path=%v %w", path, err)
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("failed to remove file: path=%v %w", path, err)
	}
	return nil
}

func (pr *Prover) removeUnfinalizedEnclaveKeyInfo(ctx context.Context) error {
	path := pr.lastEnclaveKeyInfoFilePath(false)
	pr.getLogger().InfoContext(ctx, "remove unfinalized enclave key info", "path", path)
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to stat file: path=%v %w", path, err)
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("failed to remove file: path=%v %w", path, err)
	}
	return nil
}

func (pr *Prover) removeEnclaveKeyInfos(ctx context.Context) error {
	if err := pr.removeFinalizedEnclaveKeyInfo(ctx); err != nil {
		return err
	}
	if err := pr.removeUnfinalizedEnclaveKeyInfo(ctx); err != nil {
		return err
	}
	return nil
}
