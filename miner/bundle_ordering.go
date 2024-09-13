package miner

import (
	"container/heap"
	"math/big"

	builderTypes "github.com/ethereum/go-ethereum/builder/types"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/txpool"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/holiman/uint256"
)

type _Order interface {
	AsTx() *txpool.LazyTransaction
	AsBundle() *builderTypes.SimulatedBundle
}

type _TxOrder struct {
	tx *txpool.LazyTransaction
}

func (o _TxOrder) AsTx() *txpool.LazyTransaction           { return o.tx }
func (o _TxOrder) AsBundle() *builderTypes.SimulatedBundle { return nil }

type _BundleOrder struct {
	bundle *builderTypes.SimulatedBundle
}

func (o _BundleOrder) AsTx() *txpool.LazyTransaction           { return nil }
func (o _BundleOrder) AsBundle() *builderTypes.SimulatedBundle { return o.bundle }

// orderWithMinerFee wraps a transaction with its gas price or effective miner gasTipCap
type orderWithMinerFee struct {
	order _Order
	from  common.Address
	fees  *uint256.Int
}

func (t *orderWithMinerFee) Tx() *txpool.LazyTransaction {
	return t.order.AsTx()
}

func (t *orderWithMinerFee) Bundle() *builderTypes.SimulatedBundle {
	return t.order.AsBundle()
}

func (t *orderWithMinerFee) Price() *uint256.Int {
	return new(uint256.Int).Set(t.fees)
}

func (t *orderWithMinerFee) Profit(baseFee *uint256.Int, gasUsed uint64) *uint256.Int {
	if tx := t.Tx(); tx != nil {
		profit := new(uint256.Int).Set(t.fees)
		if gasUsed != 0 {
			profit.Mul(profit, new(uint256.Int).SetUint64(gasUsed))
		} else {
			profit.Mul(profit, new(uint256.Int).SetUint64(tx.Gas))
		}
		return profit
	} else if bundle := t.Bundle(); bundle != nil {
		return bundle.TotalEth
	} else {
		panic("profit called on unsupported order type")
	}
}

// SetPrice sets the miner fee of the wrapped transaction.
func (t *orderWithMinerFee) SetPrice(price *uint256.Int) {
	t.fees.Set(price)
}

// SetProfit sets the profit of the wrapped transaction.
func (t *orderWithMinerFee) SetProfit(profit *uint256.Int) {
	if bundle := t.Bundle(); bundle != nil {
		bundle.TotalEth.Set(profit)
	} else {
		panic("SetProfit called on unsupported order type")
	}
}

// NewBundleWithMinerFee creates a wrapped bundle.
func newBundleWithMinerFee(bundle *builderTypes.SimulatedBundle) (*orderWithMinerFee, error) {
	minerFee := bundle.MevGasPrice
	return &orderWithMinerFee{
		order: _BundleOrder{bundle},
		fees:  minerFee,
	}, nil
}

// newTxWithMinerFee creates a wrapped transaction, calculating the effective
// miner gasTipCap if a base fee is provided.
// Returns error in case of a negative effective miner gasTipCap.
func newTxOrderWithMinerFee(tx *txpool.LazyTransaction, from common.Address, baseFee *uint256.Int) (*orderWithMinerFee, error) {
	tip := new(uint256.Int).Set(tx.GasTipCap)
	if baseFee != nil {
		if tx.GasFeeCap.Cmp(baseFee) < 0 {
			return nil, types.ErrGasFeeCapTooLow
		}
		tip = new(uint256.Int).Sub(tx.GasFeeCap, baseFee)
		if tip.Gt(tx.GasTipCap) {
			tip = tx.GasTipCap
		}
	}
	return &orderWithMinerFee{
		order: _TxOrder{tx},
		from:  from,
		fees:  tip,
	}, nil
}

// orderByPriceAndTime implements both the sort and the heap interface, making it useful
// for all at once sorting as well as individually adding and removing elements.
type orderByPriceAndTime []*orderWithMinerFee

func (s orderByPriceAndTime) Len() int { return len(s) }
func (s orderByPriceAndTime) Less(i, j int) bool {
	// If the prices are equal, use the time the transaction was first seen for
	// deterministic sorting
	cmp := s[i].fees.Cmp(s[j].fees)
	if cmp == 0 {
		if s[i].Tx() != nil && s[j].Tx() != nil {
			return s[i].Tx().Time.Before(s[j].Tx().Time)
		} else if s[i].Bundle() != nil && s[j].Bundle() != nil {
			return s[i].Bundle().TotalGasUsed <= s[j].Bundle().TotalGasUsed
		} else if s[i].Bundle() != nil {
			return false
		}

		return true
	}
	return cmp > 0
}
func (s orderByPriceAndTime) Swap(i, j int) { s[i], s[j] = s[j], s[i] }

func (s *orderByPriceAndTime) Push(x interface{}) {
	*s = append(*s, x.(*orderWithMinerFee))
}

func (s *orderByPriceAndTime) Pop() interface{} {
	old := *s
	n := len(old)
	x := old[n-1]
	old[n-1] = nil
	*s = old[0 : n-1]
	return x
}

// ordersByPriceAndNonce represents a set of transactions that can return
// transactions in a profit-maximizing sorted order, while supporting removing
// entire batches of transactions for non-executable accounts.
type ordersByPriceAndNonce struct {
	txs     map[common.Address][]*txpool.LazyTransaction // Per account nonce-sorted list of transactions
	heads   orderByPriceAndTime                          // Next transaction for each unique account (price heap)
	signer  types.Signer                                 // Signer for the set of transactions
	baseFee *uint256.Int                                 // Current base fee
}

// newOrdersByPriceAndNonce creates a transaction set that can retrieve
// price sorted transactions in a nonce-honouring way.
//
// Note, the input map is reowned so the caller should not interact any more with
// if after providing it to the constructor.
func newOrdersByPriceAndNonce(signer types.Signer, txs map[common.Address][]*txpool.LazyTransaction, bundles []builderTypes.SimulatedBundle, baseFee *big.Int) *ordersByPriceAndNonce {
	// Convert the basefee from header format to uint256 format
	var baseFeeUint *uint256.Int
	if baseFee != nil {
		baseFeeUint = uint256.MustFromBig(baseFee)
	}
	// Initialize a price and received time based heap with the head transactions
	heads := make(orderByPriceAndTime, 0, len(txs))

	for i := range bundles {
		wrapped, err := newBundleWithMinerFee(&bundles[i])
		if err != nil {
			continue
		}
		heads = append(heads, wrapped)
	}

	for from, accTxs := range txs {
		wrapped, err := newTxOrderWithMinerFee(accTxs[0], from, baseFeeUint)
		if err != nil {
			delete(txs, from)
			continue
		}
		heads = append(heads, wrapped)
		txs[from] = accTxs[1:]
	}
	heap.Init(&heads)

	// Assemble and return the transaction set
	return &ordersByPriceAndNonce{
		txs:     txs,
		heads:   heads,
		signer:  signer,
		baseFee: baseFeeUint,
	}
}

// Peek returns the next transaction by price.
func (t *ordersByPriceAndNonce) Peek() *orderWithMinerFee {
	if len(t.heads) == 0 {
		return nil
	}
	return t.heads[0]
}

// Shift replaces the current best head with the next one from the same account.
func (t *ordersByPriceAndNonce) Shift() {
	acc := t.heads[0].from
	if txs, ok := t.txs[acc]; ok && len(txs) > 0 {
		if wrapped, err := newTxOrderWithMinerFee(txs[0], acc, t.baseFee); err == nil {
			t.heads[0], t.txs[acc] = wrapped, txs[1:]
			heap.Fix(&t.heads, 0)
			return
		}
	}
	heap.Pop(&t.heads)
}

// Pop removes the best transaction, *not* replacing it with the next one from
// the same account. This should be used when a transaction cannot be executed
// and hence all subsequent ones should be discarded from the same account.
func (t *ordersByPriceAndNonce) Pop() {
	heap.Pop(&t.heads)
}

// ShiftAndPushByAccountForTx attempts to update the transaction list associated with a given account address
// based on the input transaction account. If the associated account exists and has additional transactions,
// the top of the transaction list is popped and pushed to the heap.
// Note that this operation should only be performed when the head transaction on the heap is different from the
// input transaction. This operation is useful in scenarios where the current best head transaction for an account
// was already popped from the heap and we want to process the next one from the same account.
func (t *ordersByPriceAndNonce) ShiftAndPushByAccountForTx(tx *types.Transaction) {
	if tx == nil {
		return
	}

	acc, _ := types.Sender(t.signer, tx)
	if txs, exists := t.txs[acc]; exists && len(txs) > 0 {
		if wrapped, err := newTxWithMinerFee(txs[0], acc, t.baseFee); err == nil {
			t.txs[acc] = txs[1:]
			heap.Push(&t.heads, wrapped)
		}
	}
}

func (t *ordersByPriceAndNonce) Push(tx *orderWithMinerFee) {
	if tx == nil {
		return
	}

	heap.Push(&t.heads, tx)
}

// Empty returns if the price heap is empty. It can be used to check it simpler
// than calling peek and checking for nil return.
func (t *ordersByPriceAndNonce) Empty() bool {
	return len(t.heads) == 0
}

// Clear removes the entire content of the heap.
func (t *ordersByPriceAndNonce) Clear() {
	t.heads, t.txs = nil, nil
}
