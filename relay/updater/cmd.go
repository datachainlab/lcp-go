package updater

import (
	"fmt"
	"strconv"
	"time"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/hyperledger-labs/yui-relayer/config"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	// SHFU cache flags
	flagDBPath         = "db_path"
	flagForce          = "force"
	flagGRPCAddr       = "grpc_addr"
	flagUpdateInterval = "update_interval"
	flagCacheSize      = "cache_size"
	flagHeight         = "height"
)

// UpdateClientCacheCmd creates the update-client-cache command (alias for shfu-cache)
func UpdateClientCacheCmd(ctx *config.Context) *cobra.Command {
	return SHFUCacheCmd(ctx)
}

// SHFUCacheCmd creates the shfu-cache command with subcommands
func SHFUCacheCmd(ctx *config.Context) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "shfu-cache",
		Short: "SHFU cache management commands",
	}

	cmd.AddCommand(
		cacheCmd(ctx),
		serverCmd(ctx),
		queryLCPCmd(ctx),
		queryChainCmd(ctx),
	)

	return cmd
}

func cacheCmd(ctx *config.Context) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cache [chain-id]",
		Short: "Cache SetupHeadersForUpdate results to SQLite",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return fmt.Errorf("chain ID is required")
			}

			targetChainID := args[0]

			// Get the target chain by chain ID
			target, err := ctx.Config.GetChain(targetChainID)
			if err != nil {
				return fmt.Errorf("chain ID '%s' not found in configuration: %w", targetChainID, err)
			}

			dbPath := viper.GetString(flagDBPath)
			if dbPath == "" {
				dbPath = "./shfu_cache.db"
			}

			height := viper.GetUint64(flagHeight)
			force := viper.GetBool(flagForce)

			opts := UpdateClientCacheOptions{
				DBPath: dbPath,
				Height: height,
				Force:  force,
			}

			return CacheUpdateClient(cmd.Context(), target, opts)
		},
	}
	cmd = dbPathFlag(heightFlag(forceFlag(cmd)))
	return cmd
}

func serverCmd(ctx *config.Context) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "server [chain-id]",
		Short: "Start SetupHeadersForUpdate cache server",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return fmt.Errorf("chain ID is required")
			}

			targetChainID := args[0]

			// Get the target chain by chain ID
			target, err := ctx.Config.GetChain(targetChainID)
			if err != nil {
				return fmt.Errorf("chain ID '%s' not found in configuration: %w", targetChainID, err)
			}

			dbPath := viper.GetString(flagDBPath)
			if dbPath == "" {
				dbPath = "./shfu_cache.db"
			}

			grpcAddr := viper.GetString(flagGRPCAddr)
			if grpcAddr == "" {
				grpcAddr = "localhost:9090"
			}

			updateInterval := viper.GetDuration(flagUpdateInterval)
			if updateInterval == 0 {
				updateInterval = 30 * time.Second
			}

			cacheSize := viper.GetInt(flagCacheSize)
			if cacheSize == 0 {
				cacheSize = 1000
			}

			opts := UpdateClientServerOptions{
				DBPath:         dbPath,
				GRPCAddr:       grpcAddr,
				UpdateInterval: updateInterval,
				CacheSize:      cacheSize,
			}

			return StartUpdateClientServer(cmd.Context(), target, opts)
		},
	}
	cmd = cacheSizeFlag(updateIntervalFlag(grpcAddrFlag(dbPathFlag(cmd))))
	return cmd
}

func queryLCPCmd(ctx *config.Context) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "query-lcp [chain-id] [counterparty-height]",
		Short: "Test existing SetupHeadersForUpdate call (for testing purposes)",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 2 {
				return fmt.Errorf("chain ID and counterparty height are required")
			}

			targetChainID := args[0]
			counterpartyHeightStr := args[1]

			// Parse counterparty height
			counterpartyHeight, err := strconv.ParseUint(counterpartyHeightStr, 10, 64)
			if err != nil {
				return fmt.Errorf("invalid counterparty height '%s': %w", counterpartyHeightStr, err)
			}

			// Get the target chain by chain ID
			target, err := ctx.Config.GetChain(targetChainID)
			if err != nil {
				return fmt.Errorf("chain ID '%s' not found in configuration: %w", targetChainID, err)
			}

			opts := QueryLCPOptions{
				Height: counterpartyHeight,
			}

			return QueryLCP(cmd.Context(), target, opts)
		},
	}
	return cmd
}

func queryChainCmd(ctx *config.Context) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "query-chain [path-name] [chain-id]",
		Short: "Query chain information including latest consensus state",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			chains, _, _, err := ctx.Config.ChainsFromPath(args[0])
			if err != nil {
				return err
			}
			target := chains[args[1]]

			pathName := args[0]
			targetChainID := args[1]

			// Get the path configuration to extract channel ID
			path, exists := ctx.Config.Paths[pathName]
			if !exists {
				return fmt.Errorf("path '%s' not found in configuration", pathName)
			}

			// Determine the channel ID based on the chain ID and path configuration
			var channelID string
			if path.Src.ChainID == targetChainID {
				channelID = path.Src.ChannelID
			} else if path.Dst.ChainID == targetChainID {
				channelID = path.Dst.ChannelID
			} else {
				return fmt.Errorf("chain ID '%s' not found in path '%s' configuration", targetChainID, pathName)
			}

			// Create client.Context using cosmos-sdk's GetClientQueryContext
			clientCtx, err := client.GetClientQueryContext(cmd)
			if err != nil {
				return fmt.Errorf("failed to get client query context: %w", err)
			}

			// Query chain information with path and channel information
			opts := QueryChainOptions{
				PathName:  pathName,
				ChannelID: channelID,
			}

			return QueryChain(cmd.Context(), target, clientCtx, opts)
		},
	}
	return cmd
}

// Flag functions
func heightFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().Uint64(flagHeight, 0, "a height to restore")
	if err := viper.BindPFlag(flagHeight, cmd.Flags().Lookup(flagHeight)); err != nil {
		panic(err)
	}
	return cmd
}

func forceFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().Bool(flagForce, false, "force update cache even if entry exists")
	if err := viper.BindPFlag(flagForce, cmd.Flags().Lookup(flagForce)); err != nil {
		panic(err)
	}
	return cmd
}

func dbPathFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().String(flagDBPath, "", "path to SQLite database file")
	if err := viper.BindPFlag(flagDBPath, cmd.Flags().Lookup(flagDBPath)); err != nil {
		panic(err)
	}
	return cmd
}

func grpcAddrFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().String(flagGRPCAddr, "", "gRPC server address")
	if err := viper.BindPFlag(flagGRPCAddr, cmd.Flags().Lookup(flagGRPCAddr)); err != nil {
		panic(err)
	}
	return cmd
}

func updateIntervalFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().Duration(flagUpdateInterval, 0, "automatic update interval")
	if err := viper.BindPFlag(flagUpdateInterval, cmd.Flags().Lookup(flagUpdateInterval)); err != nil {
		panic(err)
	}
	return cmd
}

func cacheSizeFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().Int(flagCacheSize, 0, "memory cache size")
	if err := viper.BindPFlag(flagCacheSize, cmd.Flags().Lookup(flagCacheSize)); err != nil {
		panic(err)
	}
	return cmd
}
