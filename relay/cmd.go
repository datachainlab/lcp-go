package relay

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/cosmos/cosmos-sdk/client/flags"
	"github.com/ethereum/go-ethereum/common"
	"github.com/hyperledger-labs/yui-relayer/config"
	"github.com/hyperledger-labs/yui-relayer/core"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	flagSrc                     = "src"
	flagHeight                  = "height"
	flagRetryInterval           = "retry_interval"
	flagRetryMaxAttempts        = "retry_max_attempts"
	flagELCClientID             = "elc_client_id"
	flagNewOperators            = "new_operators"
	flagNonce                   = "nonce"
	flagThresholdNumerator      = "threshold_numerator"
	flagThresholdDenominator    = "threshold_denominator"
	flagPermissionlessOperators = "permissionless_operators"
)

func LCPCmd(ctx *config.Context) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "lcp",
		Short: "LCP commands",
	}

	cmd.AddCommand(
		createELCCmd(ctx),
		updateELCCmd(ctx),
		restoreELCCmd(ctx),
		queryELCCmd(ctx),
		flags.LineBreak,
		availableEnclaveKeysCmd(ctx),
		updateEnclaveKeyCmd(ctx),
		activateClientCmd(ctx),
		removeEnclaveKeyInfoCmd(ctx),
		updateOperatorsCmd(ctx),
	)

	return cmd
}

func availableEnclaveKeysCmd(ctx *config.Context) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "available-enclave-keys [path]",
		Short: "List available enclave keys",
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
			ekis, err := prover.doAvailableEnclaveKeys(cmd.Context())
			if err != nil {
				return err
			}
			bz, err := json.Marshal(ekis)
			if err != nil {
				return err
			}
			fmt.Println(string(bz))
			return nil
		},
	}
	return srcFlag(cmd)
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
			return prover.UpdateEKIIfNeeded(cmd.Context(), verifier)
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
				pathEnd = path.Dst
				target, counterparty = c[src], c[dst]
			} else {
				pathEnd = path.Src
				target, counterparty = c[dst], c[src]
			}
			return activateClient(cmd.Context(), pathEnd, target, counterparty, viper.GetDuration(flagRetryInterval), viper.GetUint(flagRetryMaxAttempts))
		},
	}
	return retryMaxAttemptsFlag(retryIntervalFlag(srcFlag(cmd)))
}

func createELCCmd(ctx *config.Context) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "create-elc [path]",
		Short: "Create ELC client",
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
			var elcClientID string
			if viper.GetString(flagELCClientID) != "" {
				elcClientID = viper.GetString(flagELCClientID)
			} else {
				elcClientID = prover.config.ElcClientId
			}
			out, err := prover.doCreateELC(cmd.Context(), elcClientID, viper.GetUint64(flagHeight))
			if err != nil {
				return err
			}
			bz, err := json.Marshal(out)
			if err != nil {
				return err
			}
			fmt.Println(string(bz))
			return nil
		},
	}
	cmd = elcClientIDFlag(heightFlag(srcFlag(cmd)))
	cmd.MarkFlagRequired(flagELCClientID)
	return cmd
}

func updateELCCmd(ctx *config.Context) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "update-elc [path]",
		Short: "Update ELC client",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, src, dst, err := ctx.Config.ChainsFromPath(args[0])
			if err != nil {
				return err
			}
			var (
				target *core.ProvableChain
			)
			if viper.GetBool(flagSrc) {
				target = c[src]
			} else {
				target = c[dst]
			}
			prover := target.Prover.(*Prover)
			var elcClientID string
			if id := viper.GetString(flagELCClientID); id != "" {
				elcClientID = id
			} else {
				elcClientID = prover.config.ElcClientId
			}
			out, err := prover.doUpdateELC(cmd.Context(), elcClientID)
			if err != nil {
				return err
			}
			bz, err := json.Marshal(out)
			if err != nil {
				return err
			}
			fmt.Println(string(bz))
			return nil
		},
	}
	return elcClientIDFlag(srcFlag(cmd))
}

func queryELCCmd(ctx *config.Context) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "query-elc [path]",
		Short: "Query ELC client",
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
			var elcClientID string
			if id := viper.GetString(flagELCClientID); id != "" {
				elcClientID = id
			} else {
				elcClientID = prover.config.ElcClientId
			}
			out, err := prover.doQueryELC(cmd.Context(), elcClientID)
			if err != nil {
				return err
			}
			bz, err := json.Marshal(out)
			if err != nil {
				return err
			}
			fmt.Println(string(bz))
			return nil
		},
	}
	return elcClientIDFlag(srcFlag(cmd))
}

func restoreELCCmd(ctx *config.Context) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "restore-elc [path]",
		Short: "Restore ELC client state with the latest height of the LCP Client on the counterparty chain",
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
			var elcClientID string
			if id := viper.GetString(flagELCClientID); id != "" {
				elcClientID = id
			} else {
				elcClientID = prover.config.ElcClientId
			}
			return prover.restoreELC(cmd.Context(), verifier, elcClientID, viper.GetUint64(flagHeight))
		},
	}
	return elcClientIDFlag(heightFlag(srcFlag(cmd)))
}

func removeEnclaveKeyInfoCmd(ctx *config.Context) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "remove-eki [path]",
		Short: "Remove finalized and unfinalized EKIs in the relayer's home directory",
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
			return prover.removeEnclaveKeyInfos(cmd.Context())
		},
	}
	return srcFlag(cmd)
}

func updateOperatorsCmd(ctx *config.Context) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "update-operators [path]",
		Short: "Update operators",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, src, dst, err := ctx.Config.ChainsFromPath(args[0])
			if err != nil {
				return err
			}
			var (
				target       *core.ProvableChain
				counterparty *core.ProvableChain
			)
			if viper.GetBool(flagSrc) {
				target = c[src]
				counterparty = c[dst]
			} else {
				target = c[dst]
				counterparty = c[src]
			}
			prover := target.Prover.(*Prover)

			newOperators := viper.GetStringSlice(flagNewOperators)
			viper.GetBool(flagPermissionlessOperators)
			if len(newOperators) == 0 && !viper.GetBool(flagPermissionlessOperators) {
				return fmt.Errorf("either new operators or permissionless operators must be provided")
			} else if len(newOperators) > 0 && viper.GetBool(flagPermissionlessOperators) {
				return fmt.Errorf("both new operators and permissionless operators cannot be provided")
			}
			var newOpAddrs []common.Address
			for _, op := range newOperators {
				if !common.IsHexAddress(op) {
					return fmt.Errorf("invalid operator address: %s", op)
				}
				newOpAddrs = append(newOpAddrs, common.HexToAddress(op))
			}
			threshold := Fraction{
				Numerator:   viper.GetUint64(flagThresholdNumerator),
				Denominator: viper.GetUint64(flagThresholdDenominator),
			}
			nonce := viper.GetUint64(flagNonce)
			return prover.updateOperators(cmd.Context(), counterparty, nonce, newOpAddrs, threshold)
		},
	}
	cmd = thresholdFlag(
		nonceFlag(
			permissionlessOperatorsFlag(
				newOperatorsFlag(
					srcFlag(cmd),
				),
			),
		),
	)
	cmd.MarkFlagRequired(flagThresholdNumerator)
	cmd.MarkFlagRequired(flagThresholdDenominator)
	cmd.MarkFlagRequired(flagNonce)
	return cmd
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

func retryIntervalFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().DurationP(flagRetryInterval, "", time.Second, "a retry interval duration")
	if err := viper.BindPFlag(flagRetryInterval, cmd.Flags().Lookup(flagRetryInterval)); err != nil {
		panic(err)
	}
	return cmd
}

func retryMaxAttemptsFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().IntP(flagRetryMaxAttempts, "", 0, "a maximum number of retry attempts")
	if err := viper.BindPFlag(flagRetryMaxAttempts, cmd.Flags().Lookup(flagRetryMaxAttempts)); err != nil {
		panic(err)
	}
	return cmd
}

func elcClientIDFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().StringP(flagELCClientID, "", "", "a client ID of the ELC client")
	if err := viper.BindPFlag(flagELCClientID, cmd.Flags().Lookup(flagELCClientID)); err != nil {
		panic(err)
	}
	return cmd
}

func newOperatorsFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().StringSliceP(flagNewOperators, "", nil, "new operator addresses")
	if err := viper.BindPFlag(flagNewOperators, cmd.Flags().Lookup(flagNewOperators)); err != nil {
		panic(err)
	}
	return cmd
}

func nonceFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().Uint64P(flagNonce, "", 0, "a nonce")
	if err := viper.BindPFlag(flagNonce, cmd.Flags().Lookup(flagNonce)); err != nil {
		panic(err)
	}
	return cmd
}

func thresholdFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().Uint64P(flagThresholdNumerator, "", 0, "a numerator of new threshold")
	cmd.Flags().Uint64P(flagThresholdDenominator, "", 0, "a denominator of new threshold")
	if err := viper.BindPFlag(flagThresholdNumerator, cmd.Flags().Lookup(flagThresholdNumerator)); err != nil {
		panic(err)
	}
	if err := viper.BindPFlag(flagThresholdDenominator, cmd.Flags().Lookup(flagThresholdDenominator)); err != nil {
		panic(err)
	}
	return cmd
}

func permissionlessOperatorsFlag(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().BoolP(flagPermissionlessOperators, "", false, "a boolean value whether the new operators are permissionless")
	if err := viper.BindPFlag(flagPermissionlessOperators, cmd.Flags().Lookup(flagPermissionlessOperators)); err != nil {
		panic(err)
	}
	return cmd
}
