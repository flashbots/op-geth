package miner

import (
	"errors"
	"math/big"
	"sync/atomic"

	builderTypes "github.com/ethereum/go-ethereum/builder/types"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/txpool"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
)

const (
	shiftTx = 1
	popTx   = 2
)

var (
	errMevGasPriceNotSet = errors.New("mev gas price not set")
	errInterrupt         = errors.New("miner worker interrupted")
	errNoPrivateKey      = errors.New("no private key provided")
)

// environmentDiff is a helper struct used to apply transactions to a block using a copy of the state at that block
type environmentDiff struct {
	baseEnvironment *environment
	header          *types.Header
	gasPool         *core.GasPool  // available gas used to pack transactions
	state           *state.StateDB // apply state changes here
	profit          *uint256.Int
	newTxs          []*types.Transaction
	newReceipts     []*types.Receipt
	newSidecars     []*types.BlobTxSidecar
	newBlobs        int
}

func newEnvironmentDiff(env *environment) *environmentDiff {
	gasPool := new(core.GasPool).AddGas(env.gasPool.Gas())
	return &environmentDiff{
		baseEnvironment: env,
		header:          types.CopyHeader(env.header),
		gasPool:         gasPool,
		state:           env.state.Copy(),
		profit:          new(uint256.Int),
	}
}

func (envDiff *environmentDiff) copy() *environmentDiff {
	gasPool := new(core.GasPool).AddGas(envDiff.gasPool.Gas())

	return &environmentDiff{
		baseEnvironment: envDiff.baseEnvironment,
		header:          types.CopyHeader(envDiff.header),
		gasPool:         gasPool,
		state:           envDiff.state.Copy(),
		profit:          new(uint256.Int).Set(envDiff.profit),
		newTxs:          envDiff.newTxs[:],
		newReceipts:     envDiff.newReceipts[:],
		newSidecars:     envDiff.newSidecars[:],
		newBlobs:        envDiff.newBlobs,
	}
}

func (envDiff *environmentDiff) applyToBaseEnv() {
	env := envDiff.baseEnvironment
	env.gasPool = new(core.GasPool).AddGas(envDiff.gasPool.Gas())
	env.header = envDiff.header
	env.state = envDiff.state
	env.tcount += len(envDiff.newTxs)
	env.txs = append(env.txs, envDiff.newTxs...)
	env.receipts = append(env.receipts, envDiff.newReceipts...)
	env.sidecars = append(env.sidecars, envDiff.newSidecars...)
	env.blobs += envDiff.newBlobs
}

func (envDiff *environmentDiff) commitBlobTx(tx *types.Transaction, chainConfig *params.ChainConfig, chain *core.BlockChain) (*types.Receipt, int, error) {
	sc := tx.BlobTxSidecar()
	if sc == nil {
		return nil, popTx, errors.New("blob transaction without blobs in miner")
	}
	// Checking against blob gas limit: It's kind of ugly to perform this check here, but there
	// isn't really a better place right now. The blob gas limit is checked at block validation time
	// and not during execution. This means core.ApplyTransaction will not return an error if the
	// tx has too many blobs. So we have to explicitly check it here.
	if (envDiff.newBlobs+len(sc.Blobs))*params.BlobTxBlobGasPerBlob > params.MaxBlobGasPerBlock {
		return nil, popTx, errors.New("max data blobs reached")
	}
	receipt, txType, err := envDiff.commitTxCommon(tx, chainConfig, chain)
	if err != nil {
		return nil, txType, err
	}

	envDiff.newTxs = append(envDiff.newTxs, tx.WithoutBlobTxSidecar())
	envDiff.newSidecars = append(envDiff.newSidecars, sc)
	envDiff.newBlobs += len(sc.Blobs)
	*envDiff.header.BlobGasUsed += receipt.BlobGasUsed
	return receipt, txType, nil
}

// commitTxCommon is common logic to commit transaction to envDiff
func (envDiff *environmentDiff) commitTxCommon(tx *types.Transaction, chainConfig *params.ChainConfig, chain *core.BlockChain) (*types.Receipt, int, error) {
	header := envDiff.header
	coinbase := &envDiff.baseEnvironment.coinbase
	signer := envDiff.baseEnvironment.signer

	gasPrice, err := tx.EffectiveGasTip(header.BaseFee)
	if err != nil {
		return nil, shiftTx, err
	}

	envDiff.state.SetTxContext(tx.Hash(), envDiff.baseEnvironment.tcount+len(envDiff.newTxs))

	snap := envDiff.state.Snapshot()
	receipt, err := core.ApplyTransaction(chainConfig, chain, coinbase, envDiff.gasPool, envDiff.state, header, tx, &header.GasUsed, *chain.GetVMConfig())

	if err != nil {
		envDiff.state.RevertToSnapshot(snap)
		switch {
		case errors.Is(err, core.ErrGasLimitReached):
			// Pop the current out-of-gas transaction without shifting in the next from the account
			from, _ := types.Sender(signer, tx)
			log.Trace("Gas limit exceeded for current block", "sender", from)
			return receipt, popTx, err

		case errors.Is(err, core.ErrNonceTooLow):
			// New head notification data race between the transaction pool and miner, shift
			from, _ := types.Sender(signer, tx)
			log.Trace("Skipping transaction with low nonce", "sender", from, "nonce", tx.Nonce())
			return receipt, shiftTx, err

		case errors.Is(err, core.ErrNonceTooHigh):
			// Reorg notification data race between the transaction pool and miner, skip account =
			from, _ := types.Sender(signer, tx)
			log.Trace("Skipping account with hight nonce", "sender", from, "nonce", tx.Nonce())
			return receipt, popTx, err

		case errors.Is(err, core.ErrTxTypeNotSupported):
			// Pop the unsupported transaction without shifting in the next from the account
			from, _ := types.Sender(signer, tx)
			log.Trace("Skipping unsupported transaction type", "sender", from, "type", tx.Type())
			return receipt, popTx, err

		case errors.Is(err, core.ErrBlobFeeCapTooLow):
			from, _ := types.Sender(signer, tx)
			log.Trace("Skipping blob transaction with fee cap less than block blob gas fee", "sender", from, "err", err.Error())
			return receipt, popTx, err

		default:
			// Strange error, discard the transaction and get the next in line (note, the
			// nonce-too-high clause will prevent us from executing in vain).
			log.Trace("Transaction failed, account skipped", "hash", tx.Hash(), "err", err)
			return receipt, shiftTx, err
		}
	}

	profit := gasPrice.Mul(gasPrice, big.NewInt(int64(receipt.GasUsed)))
	envDiff.profit = envDiff.profit.Add(envDiff.profit, uint256.MustFromBig(profit))
	envDiff.newReceipts = append(envDiff.newReceipts, receipt)

	return receipt, shiftTx, nil
}

// commit tx to envDiff
func (envDiff *environmentDiff) commitTx(tx *types.Transaction, chain *core.BlockChain) (*types.Receipt, int, error) {
	if tx.Type() == types.BlobTxType {
		return envDiff.commitBlobTx(tx, chain.Config(), chain)
	}
	receipt, skip, err := envDiff.commitTxCommon(tx, chain.Config(), chain)
	if err != nil {
		return nil, skip, err
	}
	envDiff.newTxs = append(envDiff.newTxs, tx)
	return receipt, skip, nil
}

// Commit Bundle to env diff
func (envDiff *environmentDiff) commitBundle(bundle *builderTypes.SimulatedBundle, chain *core.BlockChain, interrupt *atomic.Int32) error {
	coinbase := envDiff.baseEnvironment.coinbase
	tmpEnvDiff := envDiff.copy()

	coinbaseBalanceBefore := tmpEnvDiff.state.GetBalance(coinbase)

	profitBefore := new(uint256.Int).Set(tmpEnvDiff.profit)
	var gasUsed uint64

	for _, tx := range bundle.OriginalBundle.Txs {
		txHash := tx.Hash()
		if tmpEnvDiff.header.BaseFee != nil && tx.Type() == types.DynamicFeeTxType {
			// Sanity check for extremely large numbers
			if tx.GasFeeCap().BitLen() > 256 {
				return core.ErrFeeCapVeryHigh
			}
			if tx.GasTipCap().BitLen() > 256 {
				return core.ErrTipVeryHigh
			}
			// Ensure gasFeeCap is greater than or equal to gasTipCap.
			if tx.GasFeeCapIntCmp(tx.GasTipCap()) < 0 {
				return core.ErrTipAboveFeeCap
			}
		}

		if tx.Value().Sign() == -1 {
			return txpool.ErrNegativeValue
		}

		_, err := tx.EffectiveGasTip(envDiff.header.BaseFee)
		if err != nil {
			return err
		}

		_, err = types.Sender(envDiff.baseEnvironment.signer, tx)
		if err != nil {
			return err
		}

		if interrupt != nil && interrupt.Load() != commitInterruptNone {
			return errInterrupt
		}

		receipt, _, err := tmpEnvDiff.commitTx(tx, chain)
		if err != nil {
			log.Trace("Bundle tx error", "bundle", bundle.OriginalBundle.Hash, "tx", txHash, "err", err)
			return err
		}

		if receipt != nil {
			if receipt.Status == types.ReceiptStatusFailed && !bundle.OriginalBundle.RevertingHash(txHash) {
				// if transaction reverted and isn't specified as reverting hash, return error
				log.Trace("Bundle tx failed", "bundle", bundle.OriginalBundle.Hash, "tx", txHash, "err", err)
				return errors.New("bundle tx revert")
			}
		} else {
			// NOTE: The expectation is that a receipt is only nil if an error occurred.
			//  If there is no error but receipt is nil, there is likely a programming error.
			return errors.New("invalid receipt when no error occurred")
		}

		gasUsed += receipt.GasUsed
	}
	coinbaseBalanceAfter := tmpEnvDiff.state.GetBalance(coinbase)
	coinbaseBalanceDelta := new(uint256.Int).Sub(coinbaseBalanceAfter, coinbaseBalanceBefore)
	tmpEnvDiff.profit.Add(profitBefore, coinbaseBalanceDelta)

	if bundle.MevGasPrice == nil {
		return errMevGasPriceNotSet
	}

	if gasUsed == 0 {
		return errors.New("bundle gas used is 0")
	}

	*envDiff = *tmpEnvDiff
	return nil
}
