package miner

import (
	"math"
	"math/big"
	"testing"

	builderTypes "github.com/ethereum/go-ethereum/builder/types"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/txpool"
	"github.com/holiman/uint256"
)

func TestBuildBlockGasLimit(t *testing.T) {
	statedb, chData, signers := genTestSetup(GasLimit)
	env := newEnvironment(chData, statedb, signers.addresses[0], 21000, big.NewInt(1))
	txs := make(map[common.Address][]*txpool.LazyTransaction)

	tx1 := signers.signTx(1, 21000, big.NewInt(0), big.NewInt(1), signers.addresses[2], big.NewInt(0), []byte{})
	txs[signers.addresses[1]] = []*txpool.LazyTransaction{{
		Hash:      tx1.Hash(),
		Tx:        tx1,
		Time:      tx1.Time(),
		GasFeeCap: uint256.MustFromBig(tx1.GasFeeCap()),
		GasTipCap: uint256.MustFromBig(tx1.GasTipCap()),
	}}
	tx2 := signers.signTx(2, 21000, big.NewInt(0), big.NewInt(1), signers.addresses[2], big.NewInt(0), []byte{})
	txs[signers.addresses[2]] = []*txpool.LazyTransaction{{
		Hash:      tx2.Hash(),
		Tx:        tx2,
		Time:      tx2.Time(),
		GasFeeCap: uint256.MustFromBig(tx2.GasFeeCap()),
		GasTipCap: uint256.MustFromBig(tx2.GasTipCap()),
	}}
	tx3 := signers.signTx(3, 21000, big.NewInt(math.MaxInt), big.NewInt(math.MaxInt), signers.addresses[2], big.NewInt(math.MaxInt), []byte{})
	txs[signers.addresses[3]] = []*txpool.LazyTransaction{{
		Hash:      tx3.Hash(),
		Tx:        tx3,
		Time:      tx3.Time(),
		GasFeeCap: uint256.MustFromBig(tx3.GasFeeCap()),
		GasTipCap: uint256.MustFromBig(tx3.GasTipCap()),
	}}

	var result *environment

	envDiff := newEnvironmentDiff(env)
	orders := newOrdersByPriceAndNonce(env.signer, txs, []builderTypes.SimulatedBundle{}, env.header.BaseFee)
	miner := Miner{
		chain:       chData,
		chainConfig: chData.Config(),
	}
	miner.mergeOrdersIntoEnvDiff(envDiff, orders, nil)
	envDiff.applyToBaseEnv()

	if env.tcount != 1 {
		t.Fatalf("Incorrect tx count [found: %d]", result.tcount)
	}

}
