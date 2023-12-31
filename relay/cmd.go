package relay

import (
	"context"

	"github.com/hyperledger-labs/yui-relayer/config"
	"github.com/hyperledger-labs/yui-relayer/core"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	flagSrc    = "src"
	flagHeight = "height"
)

func LCPCmd(ctx *config.Context) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "lcp",
		Short: "LCP commands",
	}

	cmd.AddCommand(
		updateEnclaveKeyCmd(ctx),
		activateClientCmd(ctx),
		restoreELCStateCmd(ctx),
		removeEnclaveKeyInfoCmd(ctx),
	)

	return cmd
}

func updateEnclaveKeyCmd(ctx *config.Context) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "update-enclave-key [path]",
		Short: "Register an enclave key into the LCP client",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, src, dst, err := ctx.Config.ChainsFromPath(args[0])
			if err != nil {
				return err
			}
			var (
				target   *core.ProvableChain
				verifier *core.ProvableChain
			)
			if viper.GetBool(flagSrc) {
				target = c[src]
				verifier = c[dst]
			} else {
				target = c[dst]
				verifier = c[src]
			}
			prover := target.Prover.(*Prover)
			return prover.UpdateEKIfNeeded(context.TODO(), verifier)
		},
	}
	return srcFlag(cmd)
}

func activateClientCmd(ctx *config.Context) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "activate-client [path]",
		Short: "Activate the LCP client",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, src, dst, err := ctx.Config.ChainsFromPath(args[0])
			if err != nil {
				return err
			}
			path, err := ctx.Config.Paths.Get(args[0])
			if err != nil {
				return err
			}
			var (
				pathEnd      *core.PathEnd
				target       *core.ProvableChain
				counterparty *core.ProvableChain
			)
			if viper.GetBool(flagSrc) {
				pathEnd = path.Src
				target, counterparty = c[src], c[dst]
			} else {
				pathEnd = path.Dst
				target, counterparty = c[dst], c[src]
			}
			return activateClient(pathEnd, target, counterparty)
		},
	}
	return srcFlag(cmd)
}

func restoreELCStateCmd(ctx *config.Context) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "restore-elc-state [path]",
		Short: "Restore ELC state on LCP",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, src, dst, err := ctx.Config.ChainsFromPath(args[0])
			if err != nil {
				return err
			}
			var (
				target   *core.ProvableChain
				verifier *core.ProvableChain
			)
			if viper.GetBool(flagSrc) {
				target = c[src]
				verifier = c[dst]
			} else {
				target = c[dst]
				verifier = c[src]
			}
			prover := target.Prover.(*Prover)
			if err := prover.restoreELCState(context.TODO(), verifier, viper.GetUint64(flagHeight)); err != nil {
				return err
			}
			if err := prover.removeEnclaveKeyInfos(context.TODO()); err != nil {
				return err
			}
			return nil
		},
	}
	return heightFlag(srcFlag(cmd))
}

func removeEnclaveKeyInfoCmd(ctx *config.Context) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "remove-eki [path]",
		Short: "Remove finalized and unfinalized EKIs in the relayer home directory",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, src, dst, err := ctx.Config.ChainsFromPath(args[0])
			if err != nil {
				return err
			}
			var target *core.ProvableChain
			if viper.GetBool(flagSrc) {
				target = c[src]
			} else {
				target = c[dst]
			}
			prover := target.Prover.(*Prover)
			return prover.removeEnclaveKeyInfos(context.TODO())
		},
	}
	return srcFlag(cmd)
}

func srcFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().BoolP(flagSrc, "", true, "a boolean value whether src is the target chain")
	if err := viper.BindPFlag(flagSrc, cmd.Flags().Lookup(flagSrc)); err != nil {
		panic(err)
	}
	return cmd
}

func heightFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().Uint64P(flagHeight, "", 0, "a height to restore")
	if err := viper.BindPFlag(flagHeight, cmd.Flags().Lookup(flagHeight)); err != nil {
		panic(err)
	}
	return cmd
}
