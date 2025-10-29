package relay

import (
	"context"
	"fmt"
	"sync"

	"github.com/datachainlab/lcp-go/relay/shfu_storage"
)

// Re-export types from storage package for backward compatibility
type SHFURecord = shfu_storage.SHFURecord
type SHFUStorage = shfu_storage.SHFUStorage

type SHFUService struct {
	Storage SHFUStorage
}

func (srv *SHFUService) SHFUServiceRun(ctx context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	wg := &sync.WaitGroup{}
	defer wg.Wait()

	fails := make(chan error, 2)
	defer close(fails)

	wg.Add(1)
	go func() {
		defer wg.Done()
		err := srv.RunUpdater()
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

func (*SHFUService) RunUpdater() error {
	return nil
}

func (*SHFUService) RunQuerier() error {
	return nil
}

func (*SHFUService) GracefulStop(ctx context.Context) {
}
