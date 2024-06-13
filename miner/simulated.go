package miner

import (
	"errors"
	"math/big"
	"sort"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
	"github.com/holiman/uint256"
)

var (
	ErrTxFailed       = errors.New("tx failed")
	ErrNegativeProfit = errors.New("negative profit")
	ErrInvalidBundle  = errors.New("invalid bundle")
)

func (w *worker) simulateBundle(bundle types.MevBundle) (*types.SimulatedBundle, error) {
	header := w.chain.CurrentBlock()
	statedb, err := w.chain.StateAt(header.Root)
	if err != nil {
		return nil, err
	}

	gp := new(core.GasPool).AddGas(header.GasLimit)

	var (
		coinbaseDelta  = new(uint256.Int)
		coinbaseBefore *uint256.Int
		txIdx          int
		revert         []byte
		execError      string
		gasUsed        uint64
		logs           []*types.Log
		totalProfit    = new(uint256.Int)
	)
	for _, tx := range bundle.Txs {
		coinbaseDelta.Set(common.U2560)
		coinbaseBefore = statedb.GetBalance(header.Coinbase)

		if tx != nil {
			statedb.SetTxContext(tx.Hash(), txIdx)
			txIdx++
			receipt, result, err := core.ApplyTransactionWithResult(w.chainConfig, w.chain, &header.Coinbase, gp, statedb, header, tx, &gasUsed, *w.chain.GetVMConfig())
			if err != nil {
				return nil, err
			}
			revert = result.Revert()
			if result.Err != nil {
				execError = result.Err.Error()
			}
			if receipt.Status != types.ReceiptStatusSuccessful {
				return nil, ErrTxFailed
			}
			gasUsed += receipt.GasUsed
			logs = append(logs, receipt.Logs...)

		}

		coinbaseAfter := statedb.GetBalance(header.Coinbase)
		coinbaseDelta.Set(coinbaseAfter)
		coinbaseDelta.Sub(coinbaseDelta, coinbaseBefore)

		totalProfit.Add(totalProfit, coinbaseDelta)
	}

	if coinbaseDelta.Sign() < 0 {
		return nil, ErrNegativeProfit
	}
	mevGasPrice := new(uint256.Int).Div(totalProfit, new(uint256.Int).SetUint64(gasUsed))
	simBundle := &types.SimulatedBundle{
		MevGasPrice:    mevGasPrice,
		TotalProfit:    totalProfit,
		TotalGasUsed:   gasUsed,
		Logs:           logs,
		Revert:         revert,
		ExecError:      execError,
		OriginalBundle: bundle,
	}
	log.Info("simulated bundle", "bundle", bundle.Hash, "totalProfit", totalProfit, "gasUsed", gasUsed, "execError", execError)
	if revert == nil && totalProfit.Sign() >= 0 {
		w.mu.Lock()
		defer w.mu.Unlock()
		w.simulatedBundles = append(w.simulatedBundles, simBundle)
	}
	return simBundle, nil
}

func (w *worker) getTopBundle() (*types.SimulatedBundle, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	sort.SliceStable(w.simulatedBundles, func(i, j int) bool {
		return w.simulatedBundles[j].TotalProfit.Cmp(w.simulatedBundles[i].TotalProfit) < 0
	})
	if len(w.simulatedBundles) > 0 {
		return w.simulatedBundles[0], nil
	}
	return nil, ErrInvalidBundle
}

func (w *worker) filterBundles(blockNumber *big.Int) []*types.SimulatedBundle {
	w.mu.Lock()
	defer w.mu.Unlock()

	// returned values
	var ret []*types.SimulatedBundle

	for _, bundle := range w.simulatedBundles {
		log.Info("filtering bundle", "bundle", bundle.OriginalBundle.Hash, "block", bundle.OriginalBundle.BlockNumber, "current", blockNumber.String())
		if bundle.OriginalBundle.BlockNumber.Cmp(blockNumber) < 0 {
			continue
		}

		ret = append(ret, bundle)
	}
	w.simulatedBundles = ret
	sort.SliceStable(w.simulatedBundles, func(i, j int) bool {
		return w.simulatedBundles[j].TotalProfit.Cmp(w.simulatedBundles[i].TotalProfit) > 0
	})
	return w.simulatedBundles
}
