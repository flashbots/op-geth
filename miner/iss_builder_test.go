package miner

import (
	"context"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
	"github.com/stretchr/testify/require"
)

func TestISSBuilder_ExecutionInBatches(t *testing.T) {
	w, _ := newTestWorker(t, params.TestChainConfig, ethash.NewFaker(), rawdb.NewMemoryDatabase(), 0)

	builder, _ := NewISSBuilder(w, 250*time.Millisecond, 2*time.Second)
	args := &BuildPayloadArgs{
		Timestamp: 1,
	}

	doneCh := make(chan error)
	go func() {
		// 250/2 is 8 batches
		for i := 0; i < 8; i++ {
			select {
			case <-builder.notifyCh:
			case <-time.After(275 * time.Millisecond):
				doneCh <- fmt.Errorf("timeout")
			}
		}
		doneCh <- nil
	}()

	builder.Build(context.Background(), args)

	err := <-doneCh
	require.NoError(t, err)
}

func TestISSBuilder_MultipleTransactions(t *testing.T) {
	w, b := newTestWorker(t, params.TestChainConfig, ethash.NewFaker(), rawdb.NewMemoryDatabase(), 0)
	b.pushNewTxnToPool(t)

	builder, _ := NewISSBuilder(w, 250*time.Millisecond, 2*time.Second)
	args := &BuildPayloadArgs{
		Timestamp: 1,
	}
	payload, err := builder.Build(context.Background(), args)
	require.NoError(t, err)

	envelope := payload.Resolve()
	require.Equal(t, 2, len(envelope.ExecutionPayload.Transactions))
}

func (tB *testWorkerBackend) pushNewTxnToPool(t *testing.T) {
	if tB.nonce == 0 {
		tB.nonce = 1
	} else {
		tB.nonce++
	}

	signer := types.LatestSigner(params.TestChainConfig)

	tx2 := types.MustSignNewTx(testBankKey, signer, &types.LegacyTx{
		Nonce:    tB.nonce,
		To:       &testUserAddress,
		Value:    big.NewInt(1000),
		Gas:      params.TxGas,
		GasPrice: big.NewInt(params.InitialBaseFee),
	})
	errArr := tB.txPool.Add([]*types.Transaction{tx2}, false, false)
	require.NoError(t, errArr[0])
}
