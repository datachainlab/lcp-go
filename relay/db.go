package relay

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

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

func sanitizeClientIDForPath(clientID string) string {
	if clientID == "." || clientID == ".." {
		sum := sha256.Sum256([]byte(clientID))
		return fmt.Sprintf("_client_%x", sum[:8])
	}
	replacer := strings.NewReplacer("/", "_", "\\", "_", ":", "_")
	return replacer.Replace(clientID)
}

func (pr *Prover) dbPathForClient(clientID string) string {
	return filepath.Join(pr.dbPath(), sanitizeClientIDForPath(clientID))
}

func legacyEnclaveKeyInfoDir(basePath string) string {
	return basePath
}

func enclaveKeyInfoDirs(basePath string, clientID string) []string {
	dirs := []string{filepath.Join(basePath, sanitizeClientIDForPath(clientID))}
	legacyDir := legacyEnclaveKeyInfoDir(basePath)
	if dirs[0] != legacyDir {
		dirs = append(dirs, legacyDir)
	}
	return dirs
}

func (pr *Prover) lastEnclaveKeyInfoFilePath(clientID string, finalized bool) string {
	base := pr.dbPathForClient(clientID)
	if finalized {
		return filepath.Join(base, lastFinalizedEnclaveKeyInfoFile)
	} else {
		return filepath.Join(base, lastUnfinalizedEnclaveKeyInfoFile)
	}
}

func enclaveKeyInfoFileName(finalized bool) string {
	if finalized {
		return lastFinalizedEnclaveKeyInfoFile
	}
	return lastUnfinalizedEnclaveKeyInfoFile
}

func (pr *Prover) candidateEnclaveKeyInfoPaths(clientID string, finalized bool) []string {
	base := pr.dbPath()
	filename := enclaveKeyInfoFileName(finalized)
	dirs := enclaveKeyInfoDirs(base, clientID)
	paths := make([]string, 0, len(dirs))
	for _, dir := range dirs {
		paths = append(paths, filepath.Join(dir, filename))
	}
	return paths
}

func (pr *Prover) loadLastFinalizedEnclaveKey(_ context.Context, counterparty core.Chain) (*enclave.EnclaveKeyInfo, error) {
	var notFoundPaths []string
	for i, path := range pr.candidateEnclaveKeyInfoPaths(counterparty.Path().ClientID, true) {
		bz, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				notFoundPaths = append(notFoundPaths, path)
				continue
			}
			return nil, fmt.Errorf("failed to stat file: path=%v %w", path, err)
		}
		if i > 0 {
			pr.getLogger().Info("using legacy finalized enclave key info path", "path", path)
		}
		var eki enclave.EnclaveKeyInfo
		if err := json.Unmarshal(bz, &eki); err != nil {
			return nil, fmt.Errorf("failed to unmarshal enclave key info: path=%v %w", path, err)
		}
		return &eki, nil
	}
	return nil, fmt.Errorf("%v not found: %w", strings.Join(notFoundPaths, ", "), ErrEnclaveKeyInfoNotFound)
}

func (pr *Prover) loadLastUnfinalizedEnclaveKey(_ context.Context, counterparty core.Chain) (*enclave.EnclaveKeyInfo, core.MsgID, error) {
	var notFoundPaths []string
	for i, path := range pr.candidateEnclaveKeyInfoPaths(counterparty.Path().ClientID, false) {
		bz, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				notFoundPaths = append(notFoundPaths, path)
				continue
			}
			return nil, nil, fmt.Errorf("failed to stat file: path=%v %w", path, err)
		}
		if i > 0 {
			pr.getLogger().Info("using legacy unfinalized enclave key info path", "path", path)
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
	return nil, nil, fmt.Errorf("%v not found: %w", strings.Join(notFoundPaths, ", "), ErrEnclaveKeyInfoNotFound)
}

func (pr *Prover) saveFinalizedEnclaveKeyInfo(ctx context.Context, counterparty core.Chain, eki *enclave.EnclaveKeyInfo) error {
	pr.getLogger().InfoContext(ctx, "save finalized enclave key info")
	bz, err := json.Marshal(eki)
	if err != nil {
		return fmt.Errorf("failed to marshal enclave key info: %w", err)
	}
	path := pr.lastEnclaveKeyInfoFilePath(counterparty.Path().ClientID, true)
	if err := os.MkdirAll(filepath.Dir(path), os.ModePerm); err != nil {
		return fmt.Errorf("failed to create db dir: %w", err)
	}
	if err := os.WriteFile(path, bz, 0600); err != nil {
		return fmt.Errorf("failed to write enclave key info: %w", err)
	}
	return nil
}

func (pr *Prover) saveUnfinalizedEnclaveKeyInfo(ctx context.Context, counterparty core.Chain, eki *enclave.EnclaveKeyInfo, msgID core.MsgID) error {
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
	path := pr.lastEnclaveKeyInfoFilePath(counterparty.Path().ClientID, false)
	if err := os.MkdirAll(filepath.Dir(path), os.ModePerm); err != nil {
		return fmt.Errorf("failed to create db dir: %w", err)
	}
	if err := os.WriteFile(path, bz, 0600); err != nil {
		return fmt.Errorf("failed to write enclave key info: %w", err)
	}
	return nil
}

func (pr *Prover) removeFinalizedEnclaveKeyInfo(ctx context.Context, clientID string) error {
	path := pr.lastEnclaveKeyInfoFilePath(clientID, true)
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

func (pr *Prover) removeUnfinalizedEnclaveKeyInfo(ctx context.Context, clientID string) error {
	path := pr.lastEnclaveKeyInfoFilePath(clientID, false)
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

func (pr *Prover) RemoveEnclaveKeyInfos(ctx context.Context) error {
	base := pr.dbPath()
	pr.getLogger().InfoContext(ctx, "remove enclave key info cache root", "path", base)
	if _, err := os.Stat(base); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to stat dir: path=%v %w", base, err)
	}
	if err := os.RemoveAll(base); err != nil {
		return fmt.Errorf("failed to remove dir: path=%v %w", base, err)
	}
	return nil
}
