package relay

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	clienttypes "github.com/cosmos/ibc-go/v8/modules/core/02-client/types"
	"github.com/hyperledger-labs/yui-relayer/core"
)

type SHFUService struct {
	Storage      SHFUStorage
	TargetChain  *core.ProvableChain
	PollInterval time.Duration
}

// NewSHFUService creates a new SHFUService with default polling interval
func NewSHFUService(storage SHFUStorage, targetChain *core.ProvableChain) *SHFUService {
	return &SHFUService{
		Storage:      storage,
		TargetChain:  targetChain,
		PollInterval: 30 * time.Second, // Default 30 seconds polling interval
	}
}

func (srv *SHFUService) SHFUServiceRun(ctx context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// シグナルハンドリング用のチャネル
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	wg := &sync.WaitGroup{}
	defer wg.Wait()

	fails := make(chan error, 3) // シグナルハンドリング用に1つ増やす
	defer close(fails)

	// シグナルハンドリング用のgoroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		select {
		case sig := <-sigCh:
			fmt.Printf("SHFU Service received signal: %v, shutting down gracefully...\n", sig)
			cancel()
		case <-ctx.Done():
			// 他の理由でcontextがキャンセルされた場合
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		err := srv.RunUpdater(ctx)
		if err != nil {
			fails <- err
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		err := srv.RunQuerier()
		if err != nil {
			fails <- err
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		for e := range fails {
			fmt.Println("error received. stopping...")
			fmt.Println(fmt.Sprintf("error details: %+v", e))
			cancel()
		}
	}()

	<-ctx.Done()
	//slog.Info("stopping...")

	srv.GracefulStop(ctx) //only used context value
}

func (srv *SHFUService) RunUpdater(ctx context.Context) error {
	ticker := time.NewTicker(srv.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := srv.executeUpdate(ctx); err != nil {
				fmt.Printf("SHFU update failed: %v\n", err)
				return err // Return error to stop the service when no records found
			}
		}
	}
}

func (srv *SHFUService) executeUpdate(ctx context.Context) error {
	// Get the latest record to determine the fromHeight
	latestRecord, err := srv.Storage.GetLatestSHFUForChain(ctx, srv.TargetChain.ChainID())
	if err != nil {
		return fmt.Errorf("failed to get latest SHFU record: %w", err)
	}

	if latestRecord == nil {
		return fmt.Errorf("no previous SHFU records found for chain %s: cannot determine starting height", srv.TargetChain.ChainID())
	}

	// Use the ToHeight from the latest record as the new fromHeight
	fromHeight := clienttypes.Height{
		RevisionNumber: latestRecord.ToHeight.RevisionNumber,
		RevisionHeight: latestRecord.ToHeight.RevisionHeight,
	}

	// Execute SHFU and store the result
	record, err := SHFUExecuteAndStore(ctx, srv.TargetChain, fromHeight, srv.Storage)
	if err != nil {
		return fmt.Errorf("failed to execute SHFU: %w", err)
	}

	if record != nil {
		fmt.Printf("SHFU executed successfully for chain %s, from height %d-%d to height %d-%d\n",
			record.ChainID,
			record.FromHeight.RevisionNumber, record.FromHeight.RevisionHeight,
			record.ToHeight.RevisionNumber, record.ToHeight.RevisionHeight)
	}

	return nil
}

func (*SHFUService) RunQuerier() error {
	return nil
}

func (*SHFUService) GracefulStop(ctx context.Context) {
}
