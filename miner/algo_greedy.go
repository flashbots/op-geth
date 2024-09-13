package miner

import (
	"errors"
	"fmt"
	"math/big"
	"sync"
	"sync/atomic"
	"time"

	builderTypes "github.com/ethereum/go-ethereum/builder/types"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/misc"
	"github.com/ethereum/go-ethereum/consensus/misc/eip4844"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/txpool"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
)

// generateBuilderWork generates a sealing block based on the given parameters.
func (miner *Miner) generateBuilderWork(params *generateParams) *newPayloadResult {
	start := time.Now()
	profit := new(uint256.Int)
	bundles := []builderTypes.SimulatedBundle{}

	work, err := miner.prepareWork(params)
	if err != nil {
		return &newPayloadResult{err: err}
	}
	if work.gasPool == nil {
		gasLimit := miner.config.EffectiveGasCeil
		if gasLimit == 0 || gasLimit > work.header.GasLimit {
			gasLimit = work.header.GasLimit
		}
		work.gasPool = new(core.GasPool).AddGas(gasLimit)
	}

	misc.EnsureCreate2Deployer(miner.chainConfig, work.header.Time, work.state)

	for _, tx := range params.txs {
		from, _ := types.Sender(work.signer, tx)
		work.state.SetTxContext(tx.Hash(), work.tcount)
		err = miner.commitTransaction(work, tx)
		if err != nil {
			return &newPayloadResult{err: fmt.Errorf("failed to force-include tx: %s type: %d sender: %s nonce: %d, err: %w", tx.Hash(), tx.Type(), from, tx.Nonce(), err)}
		}
		work.tcount++
	}
	if !params.noTxs {
		// use shared interrupt if present
		interrupt := params.interrupt
		if interrupt == nil {
			interrupt = new(atomic.Int32)
		}
		timer := time.AfterFunc(max(minRecommitInterruptInterval, miner.config.Recommit), func() {
			interrupt.Store(commitInterruptTimeout)
		})

		bundles, profit, err = miner.fillTransactionsAndBundles(interrupt, work, params.txs)
		timer.Stop() // don't need timeout interruption any more
		if errors.Is(err, errBlockInterruptedByTimeout) {
			log.Warn("Block building is interrupted", "allowance", common.PrettyDuration(miner.config.Recommit))
		} else if errors.Is(err, errBlockInterruptedByResolve) {
			log.Info("Block building got interrupted by payload resolution")
		} else if err != nil {
			return &newPayloadResult{err: err}
		}
	}
	if intr := params.interrupt; intr != nil && params.isUpdate && intr.Load() != commitInterruptNone {
		return &newPayloadResult{err: errInterruptedUpdate}
	}

	body := types.Body{Transactions: work.txs, Withdrawals: params.withdrawals}
	block, err := miner.engine.FinalizeAndAssemble(miner.chain, work.header, work.state, &body, work.receipts)
	if err != nil {
		return &newPayloadResult{err: err}
	}

	log.Info("Block finalized and assembled", "num", block.Number().String(), "profit", ethIntToFloat(profit),
		"txs", len(work.txs), "bundles", len(bundles), "gasUsed", block.GasUsed(), "time", time.Since(start))

	return &newPayloadResult{
		block:    block,
		fees:     profit.ToBig(),
		sidecars: work.sidecars,
		stateDB:  work.state,
		receipts: work.receipts,
	}
}

func (miner *Miner) mergeOrdersIntoEnvDiff(envDiff *environmentDiff, orders *ordersByPriceAndNonce, interrupt *atomic.Int32) []builderTypes.SimulatedBundle {
	var (
		usedBundles []builderTypes.SimulatedBundle
	)
	for {
		order := orders.Peek()
		if order == nil {
			break
		}

		if laxyTx := order.Tx(); laxyTx != nil {
			tx := laxyTx.Resolve()
			if tx == nil {
				log.Trace("Ignoring evicted transaction", "hash", laxyTx.Hash)
				orders.Pop()
				continue
			}
			receipt, skip, err := envDiff.commitTx(tx, miner.chain)
			switch skip {
			case shiftTx:
				orders.Shift()
			case popTx:
				orders.Pop()
			}

			if err != nil {
				log.Trace("could not apply tx", "hash", tx.Hash(), "err", err)
				continue
			}
			effGapPrice, err := tx.EffectiveGasTip(envDiff.baseEnvironment.header.BaseFee)
			if err == nil {
				log.Trace("Included tx", "EGP", effGapPrice.String(), "gasUsed", receipt.GasUsed)
			}
		} else if bundle := order.Bundle(); bundle != nil {
			err := envDiff.commitBundle(bundle, miner.chain, interrupt)
			orders.Pop()
			if err != nil {
				log.Trace("Could not apply bundle", "bundle", bundle.OriginalBundle.Hash, "err", err)
				continue
			}

			log.Trace("Included bundle", "bundleEGP", bundle.MevGasPrice.String(), "gasUsed", bundle.TotalGasUsed, "totalEth", ethIntToFloat(bundle.TotalEth))
			usedBundles = append(usedBundles, *bundle)
		}
	}
	return usedBundles
}

func (miner *Miner) fillTransactionsAndBundles(interrupt *atomic.Int32, env *environment, forcedTxs types.Transactions) ([]builderTypes.SimulatedBundle, *uint256.Int, error) {
	miner.confMu.RLock()
	tip := miner.config.GasPrice
	miner.confMu.RUnlock()

	// Retrieve the pending transactions pre-filtered by the 1559/4844 dynamic fees
	filter := txpool.PendingFilter{
		MinTip: uint256.MustFromBig(tip),
	}
	if env.header.BaseFee != nil {
		filter.BaseFee = uint256.MustFromBig(env.header.BaseFee)
	}
	if env.header.ExcessBlobGas != nil {
		filter.BlobFee = uint256.MustFromBig(eip4844.CalcBlobFee(*env.header.ExcessBlobGas))
	}

	pending := miner.txpool.Pending(filter)
	mempoolTxHashes := make(map[common.Hash]struct{})
	for _, txs := range pending {
		for _, tx := range txs {
			mempoolTxHashes[tx.Hash] = struct{}{}
		}
	}

	bundlesToConsider, err := miner.getSimulatedBundles(env)
	if err != nil {
		return nil, nil, err
	}

	start := time.Now()

	orders := newOrdersByPriceAndNonce(env.signer, pending, bundlesToConsider, env.header.BaseFee)
	envDiff := newEnvironmentDiff(env)
	usedBundles := miner.mergeOrdersIntoEnvDiff(envDiff, orders, interrupt)
	envDiff.applyToBaseEnv()

	mergeAlgoTimer.Update(time.Since(start))

	err = VerifyBundlesAtomicity(env, usedBundles, bundlesToConsider, mempoolTxHashes, forcedTxs)
	if err != nil {
		return nil, nil, err
	}
	return usedBundles, envDiff.profit, nil
}

func (miner *Miner) getSimulatedBundles(env *environment) ([]builderTypes.SimulatedBundle, error) {
	bundles := miner.txpool.MevBundles(env.header.Number, env.header.Time)

	simBundles, err := miner.simulateBundles(env, bundles)
	if err != nil {
		log.Error("Failed to simulate bundles", "err", err)
		return nil, err
	}

	return simBundles, nil
}

func (miner *Miner) simulateBundles(env *environment, bundles []builderTypes.MevBundle) ([]builderTypes.SimulatedBundle, error) {
	start := time.Now()

	simResult := make([]*builderTypes.SimulatedBundle, len(bundles))

	var wg sync.WaitGroup
	for i, bundle := range bundles {
		wg.Add(1)
		go func(idx int, bundle builderTypes.MevBundle, state *state.StateDB) {
			defer wg.Done()

			start := time.Now()

			if len(bundle.Txs) == 0 {
				return
			}
			gasPool := new(core.GasPool).AddGas(env.header.GasLimit)
			simmed, err := miner.computeBundleGas(env, bundle, state, gasPool)

			simulationMeter.Mark(1)

			if err != nil {
				simulationRevertedMeter.Mark(1)
				failedBundleSimulationTimer.UpdateSince(start)

				log.Trace("Error computing gas for a bundle", "error", err)
				return
			}
			simResult[idx] = &simmed

			simulationCommittedMeter.Mark(1)
			successfulBundleSimulationTimer.UpdateSince(start)
		}(i, bundle, env.state.Copy())
	}

	wg.Wait()

	simBundleCount := 0
	for _, bundle := range simResult {
		if bundle != nil {
			simBundleCount += 1
		}
	}

	simulatedBundles := make([]builderTypes.SimulatedBundle, 0, simBundleCount)
	for _, bundle := range simResult {
		if bundle != nil {
			simulatedBundles = append(simulatedBundles, *bundle)
		}
	}

	log.Debug("Simulated bundles", "block", env.header.Number, "allBundles", len(bundles), "okBundles", len(simulatedBundles), "time", time.Since(start))

	blockBundleSimulationTimer.Update(time.Since(start))
	blockBundleNumHistogram.Update(int64(len(bundles)))

	return simulatedBundles, nil
}

// Compute the adjusted gas price for a whole bundle
// Done by calculating all gas spent, adding transfers to the coinbase, and then dividing by gas used
func (miner *Miner) computeBundleGas(env *environment, bundle builderTypes.MevBundle, state *state.StateDB, gasPool *core.GasPool) (builderTypes.SimulatedBundle, error) {
	var totalGasUsed uint64 = 0
	var tempGasUsed uint64

	totalEth := new(uint256.Int)

	for i, tx := range bundle.Txs {
		if env.header.BaseFee != nil && tx.Type() == 2 {
			// Sanity check for extremely large numbers
			if tx.GasFeeCap().BitLen() > 256 {
				return builderTypes.SimulatedBundle{}, core.ErrFeeCapVeryHigh
			}
			if tx.GasTipCap().BitLen() > 256 {
				return builderTypes.SimulatedBundle{}, core.ErrTipVeryHigh
			}
			// Ensure gasFeeCap is greater than or equal to gasTipCap.
			if tx.GasFeeCapIntCmp(tx.GasTipCap()) < 0 {
				return builderTypes.SimulatedBundle{}, core.ErrTipAboveFeeCap
			}
		}

		state.SetTxContext(tx.Hash(), i)
		coinbaseBalanceBefore := state.GetBalance(env.coinbase)

		config := *miner.chain.GetVMConfig()
		receipt, err := core.ApplyTransaction(miner.chainConfig, miner.chain, &env.coinbase, gasPool, state, env.header, tx, &tempGasUsed, config)
		if err != nil {
			return builderTypes.SimulatedBundle{}, err
		}

		if receipt.Status == types.ReceiptStatusFailed && !containsHash(bundle.RevertingTxHashes, receipt.TxHash) {
			return builderTypes.SimulatedBundle{}, errors.New("failed tx")
		}

		totalGasUsed += receipt.GasUsed

		coinbaseBalanceAfter := state.GetBalance(env.coinbase)
		coinbaseDelta := uint256.NewInt(0).Sub(coinbaseBalanceAfter, coinbaseBalanceBefore)
		totalEth.Add(totalEth, coinbaseDelta)
	}

	return builderTypes.SimulatedBundle{
		MevGasPrice:    new(uint256.Int).Div(totalEth, new(uint256.Int).SetUint64(totalGasUsed)),
		TotalEth:       totalEth,
		TotalGasUsed:   totalGasUsed,
		OriginalBundle: bundle,
	}, nil
}

// ethIntToFloat is for formatting a uint256.Int in wei to eth
func ethIntToFloat(eth *uint256.Int) *big.Float {
	if eth == nil {
		return big.NewFloat(0)
	}
	return new(big.Float).Quo(new(big.Float).SetInt(eth.ToBig()), new(big.Float).SetInt(big.NewInt(params.Ether)))
}

func containsHash(arr []common.Hash, match common.Hash) bool {
	for _, elem := range arr {
		if elem == match {
			return true
		}
	}
	return false
}
