package miner

import (
	"crypto/ecdsa"
	"math/big"
	"math/rand"
	"testing"
	"time"

	builderTypes "github.com/ethereum/go-ethereum/builder/types"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/txpool"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/holiman/uint256"
)

func TestOrderPriceNonceSort1559(t *testing.T) {
	t.Parallel()
	testOrderPriceNonceSort(t, big.NewInt(0))
	testOrderPriceNonceSort(t, big.NewInt(5))
	testOrderPriceNonceSort(t, big.NewInt(50))
}

// Tests that transactions can be correctly sorted according to their price in
// decreasing order, but at the same time with increasing nonces when issued by
// the same account.
func testOrderPriceNonceSort(t *testing.T, baseFee *big.Int) {
	// Generate a batch of accounts to start with
	keys := make([]*ecdsa.PrivateKey, 25)
	for i := 0; i < len(keys); i++ {
		keys[i], _ = crypto.GenerateKey()
	}
	signer := types.LatestSignerForChainID(common.Big1)

	// Generate a batch of transactions with overlapping values, but shifted nonces
	groups := map[common.Address][]*txpool.LazyTransaction{}
	expectedCount := 0
	for start, key := range keys {
		addr := crypto.PubkeyToAddress(key.PublicKey)
		count := 25
		for i := 0; i < 25; i++ {
			var tx *types.Transaction
			gasFeeCap := rand.Intn(50)
			if baseFee == nil {
				tx = types.NewTx(&types.LegacyTx{
					Nonce:    uint64(start + i),
					To:       &common.Address{},
					Value:    big.NewInt(100),
					Gas:      100,
					GasPrice: big.NewInt(int64(gasFeeCap)),
					Data:     nil,
				})
			} else {
				tx = types.NewTx(&types.DynamicFeeTx{
					Nonce:     uint64(start + i),
					To:        &common.Address{},
					Value:     big.NewInt(100),
					Gas:       100,
					GasFeeCap: big.NewInt(int64(gasFeeCap)),
					GasTipCap: big.NewInt(int64(rand.Intn(gasFeeCap + 1))),
					Data:      nil,
				})
				if count == 25 && int64(gasFeeCap) < baseFee.Int64() {
					count = i
				}
			}
			tx, err := types.SignTx(tx, signer, key)
			if err != nil {
				t.Fatalf("failed to sign tx: %s", err)
			}
			groups[addr] = append(groups[addr], &txpool.LazyTransaction{
				Hash:      tx.Hash(),
				Tx:        tx,
				Time:      tx.Time(),
				GasFeeCap: uint256.MustFromBig(tx.GasFeeCap()),
				GasTipCap: uint256.MustFromBig(tx.GasTipCap()),
				Gas:       tx.Gas(),
				BlobGas:   tx.BlobGas(),
			})
		}
		expectedCount += count
	}
	// Sort the transactions and cross check the nonce ordering
	txset := newOrdersByPriceAndNonce(signer, groups, nil, baseFee)

	txs := types.Transactions{}
	for tx := txset.Peek(); tx != nil; tx = txset.Peek() {
		txs = append(txs, tx.Tx().Tx)
		txset.Shift()
	}
	if len(txs) != expectedCount {
		t.Errorf("expected %d transactions, found %d", expectedCount, len(txs))
	}
	for i, txi := range txs {
		fromi, _ := types.Sender(signer, txi)

		// Make sure the nonce order is valid
		for j, txj := range txs[i+1:] {
			fromj, _ := types.Sender(signer, txj)
			if fromi == fromj && txi.Nonce() > txj.Nonce() {
				t.Errorf("invalid nonce ordering: tx #%d (A=%x N=%v) < tx #%d (A=%x N=%v)", i, fromi[:4], txi.Nonce(), i+j, fromj[:4], txj.Nonce())
			}
		}
		// If the next tx has different from account, the price must be lower than the current one
		if i+1 < len(txs) {
			next := txs[i+1]
			fromNext, _ := types.Sender(signer, next)
			tip, err := txi.EffectiveGasTip(baseFee)
			nextTip, nextErr := next.EffectiveGasTip(baseFee)
			if err != nil || nextErr != nil {
				t.Errorf("error calculating effective tip: %v, %v", err, nextErr)
			}
			if fromi != fromNext && tip.Cmp(nextTip) < 0 {
				t.Errorf("invalid gasprice ordering: tx #%d (A=%x P=%v) < tx #%d (A=%x P=%v)", i, fromi[:4], txi.GasPrice(), i+1, fromNext[:4], next.GasPrice())
			}
		}
	}
}

// Tests that if multiple transactions have the same price, the ones seen earlier
// are prioritized to avoid network spam attacks aiming for a specific ordering.
func TestOrderTimeSort(t *testing.T) {
	t.Parallel()
	// Generate a batch of accounts to start with
	keys := make([]*ecdsa.PrivateKey, 5)
	for i := 0; i < len(keys); i++ {
		keys[i], _ = crypto.GenerateKey()
	}
	signer := types.HomesteadSigner{}

	// Generate a batch of transactions with overlapping prices, but different creation times
	groups := map[common.Address][]*txpool.LazyTransaction{}
	for start, key := range keys {
		addr := crypto.PubkeyToAddress(key.PublicKey)

		tx, _ := types.SignTx(types.NewTransaction(0, common.Address{}, big.NewInt(100), 100, big.NewInt(1), nil), signer, key)
		tx.SetTime(time.Unix(0, int64(len(keys)-start)))

		groups[addr] = append(groups[addr], &txpool.LazyTransaction{
			Hash:      tx.Hash(),
			Tx:        tx,
			Time:      tx.Time(),
			GasFeeCap: uint256.MustFromBig(tx.GasFeeCap()),
			GasTipCap: uint256.MustFromBig(tx.GasTipCap()),
			Gas:       tx.Gas(),
			BlobGas:   tx.BlobGas(),
		})
	}
	// Sort the transactions and cross check the nonce ordering
	txset := newOrdersByPriceAndNonce(signer, groups, nil, nil)

	txs := types.Transactions{}
	for tx := txset.Peek(); tx != nil; tx = txset.Peek() {
		txs = append(txs, tx.Tx().Tx)
		txset.Shift()
	}
	if len(txs) != len(keys) {
		t.Errorf("expected %d transactions, found %d", len(keys), len(txs))
	}
	for i, txi := range txs {
		fromi, _ := types.Sender(signer, txi)
		if i+1 < len(txs) {
			next := txs[i+1]
			fromNext, _ := types.Sender(signer, next)

			if txi.GasPrice().Cmp(next.GasPrice()) < 0 {
				t.Errorf("invalid gasprice ordering: tx #%d (A=%x P=%v) < tx #%d (A=%x P=%v)", i, fromi[:4], txi.GasPrice(), i+1, fromNext[:4], next.GasPrice())
			}
			// Make sure time order is ascending if the txs have the same gas price
			if txi.GasPrice().Cmp(next.GasPrice()) == 0 && txi.Time().After(next.Time()) {
				t.Errorf("invalid received time ordering: tx #%d (A=%x T=%v) > tx #%d (A=%x T=%v)", i, fromi[:4], txi.Time(), i+1, fromNext[:4], next.Time())
			}
		}
	}
}

func TestOrdersWithMinerFeeHeap(t *testing.T) {
	statedb, chData, signers := genTestSetup(GasLimit)

	env := newEnvironment(chData, statedb, signers.addresses[0], 21000, big.NewInt(1))

	txs := make(map[common.Address][]*txpool.LazyTransaction)

	tx1 := signers.signTx(1, 21000, big.NewInt(1), big.NewInt(5), signers.addresses[2], big.NewInt(0), []byte{})
	txs[signers.addresses[1]] = []*txpool.LazyTransaction{
		{
			Hash:      tx1.Hash(),
			Tx:        tx1,
			Time:      tx1.Time(),
			GasFeeCap: uint256.MustFromBig(tx1.GasFeeCap()),
			GasTipCap: uint256.MustFromBig(tx1.GasTipCap()),
		},
	}
	tx2 := signers.signTx(2, 21000, big.NewInt(4), big.NewInt(5), signers.addresses[2], big.NewInt(0), []byte{})
	txs[signers.addresses[2]] = []*txpool.LazyTransaction{
		{
			Hash:      tx2.Hash(),
			Tx:        tx2,
			Time:      tx2.Time(),
			GasFeeCap: uint256.MustFromBig(tx2.GasFeeCap()),
			GasTipCap: uint256.MustFromBig(tx2.GasTipCap()),
		},
	}

	bundle1 := builderTypes.SimulatedBundle{MevGasPrice: uint256.NewInt(3), OriginalBundle: builderTypes.MevBundle{Hash: common.HexToHash("0xb1")}}
	bundle2 := builderTypes.SimulatedBundle{MevGasPrice: uint256.NewInt(2), OriginalBundle: builderTypes.MevBundle{Hash: common.HexToHash("0xb2")}}

	orders := newOrdersByPriceAndNonce(env.signer, txs, []builderTypes.SimulatedBundle{bundle2, bundle1}, env.header.BaseFee)

	for {
		order := orders.Peek()
		if order == nil {
			return
		}

		if order.Tx() != nil {
			orders.Shift()
		} else if order.Bundle() != nil {
			orders.Pop()
		}
	}
}
