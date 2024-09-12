package miner

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math/big"
	"testing"

	builderTypes "github.com/ethereum/go-ethereum/builder/types"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/triedb"
	"github.com/holiman/uint256"
	"github.com/stretchr/testify/require"
)

const GasLimit uint64 = 30000000

var (
	// Pay proxy is a contract that sends msg.value to address specified in calldata[0..32]
	payProxyAddress = common.HexToAddress("0x1100000000000000000000000000000000000000")
	payProxyCode    = hexutil.MustDecode("0x6000600060006000346000356000f1")
	// log contract logs value that it receives
	logContractAddress = common.HexToAddress("0x2200000000000000000000000000000000000000")
	logContractCode    = hexutil.MustDecode("0x346000523460206000a1")
)

type signerList struct {
	config    *params.ChainConfig
	signers   []*ecdsa.PrivateKey
	addresses []common.Address
	nonces    []uint64
}

func (sig signerList) signTx(i int, gas uint64, gasTipCap, gasFeeCap *big.Int, to common.Address, value *big.Int, data []byte) *types.Transaction {
	txData := &types.DynamicFeeTx{
		ChainID:   sig.config.ChainID,
		Nonce:     sig.nonces[i],
		GasTipCap: gasTipCap,
		GasFeeCap: gasFeeCap,
		Gas:       gas,
		To:        &to,
		Value:     value,
		Data:      data,
	}
	sig.nonces[i] += 1

	return types.MustSignNewTx(sig.signers[i], types.LatestSigner(sig.config), txData)
}

func genSignerList(len int, config *params.ChainConfig) signerList {
	res := signerList{
		config:    config,
		signers:   make([]*ecdsa.PrivateKey, len),
		addresses: make([]common.Address, len),
		nonces:    make([]uint64, len),
	}

	for i := 0; i < len; i++ {
		privKey, err := crypto.ToECDSA(crypto.Keccak256(big.NewInt(int64(i)).Bytes()))
		if err != nil {
			panic(fmt.Sprint("cant create priv key", err))
		}
		res.signers[i] = privKey
		res.addresses[i] = crypto.PubkeyToAddress(privKey.PublicKey)
	}
	return res
}

func genGenesisAlloc(sign signerList, contractAddr []common.Address, contractCode [][]byte) types.GenesisAlloc {
	genesisAlloc := make(types.GenesisAlloc)
	for i := 0; i < len(sign.signers); i++ {
		genesisAlloc[sign.addresses[i]] = types.Account{
			Balance: big.NewInt(1000000000000000000), // 1 ether
			Nonce:   sign.nonces[i],
		}
	}

	for i, address := range contractAddr {
		genesisAlloc[address] = types.Account{
			Balance: new(big.Int),
			Code:    contractCode[i],
		}
	}

	return genesisAlloc
}

func genTestSetup(gasLimit uint64) (*state.StateDB, *core.BlockChain, signerList) {
	config := params.AllEthashProtocolChanges
	signerList := genSignerList(10, params.AllEthashProtocolChanges)
	genesisAlloc := genGenesisAlloc(signerList, []common.Address{payProxyAddress, logContractAddress}, [][]byte{payProxyCode, logContractCode})

	stateDB, chain := genTestSetupWithAlloc(config, genesisAlloc, gasLimit)
	return stateDB, chain, signerList
}

func genTestSetupWithAlloc(config *params.ChainConfig, alloc types.GenesisAlloc, gasLimit uint64) (*state.StateDB, *core.BlockChain) {
	db := rawdb.NewMemoryDatabase()

	gspec := &core.Genesis{
		Config:   config,
		Alloc:    alloc,
		GasLimit: gasLimit,
	}
	_ = gspec.MustCommit(db, triedb.NewDatabase(db, triedb.HashDefaults))

	chain, _ := core.NewBlockChain(db, &core.CacheConfig{TrieDirtyDisabled: true}, gspec, nil, ethash.NewFaker(), vm.Config{}, nil, nil)

	stateDB, _ := state.New(chain.CurrentHeader().Root, state.NewDatabase(db), nil)

	return stateDB, chain
}

func newEnvironment(chain *core.BlockChain, state *state.StateDB, coinbase common.Address, gasLimit uint64, baseFee *big.Int) *environment {
	currentBlock := chain.CurrentBlock()
	// Note the passed coinbase may be different with header.Coinbase.
	return &environment{
		signer:   types.MakeSigner(chain.Config(), currentBlock.Number, currentBlock.Time),
		state:    state,
		gasPool:  new(core.GasPool).AddGas(gasLimit),
		coinbase: coinbase,
		header: &types.Header{
			Coinbase:   coinbase,
			ParentHash: currentBlock.Hash(),
			Number:     new(big.Int).Add(currentBlock.Number, big.NewInt(1)),
			GasLimit:   gasLimit,
			GasUsed:    0,
			BaseFee:    baseFee,
			Difficulty: big.NewInt(0),
		},
	}
}

func simulateBundle(env *environment, bundle builderTypes.MevBundle, chain *core.BlockChain) (builderTypes.SimulatedBundle, error) {
	stateDB := env.state
	gasPool := new(core.GasPool).AddGas(env.header.GasLimit)

	var totalGasUsed uint64
	totalEth := uint256.NewInt(0)

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

		stateDB.SetTxContext(tx.Hash(), i+env.tcount)
		coinbaseBalanceBefore := stateDB.GetBalance(env.coinbase)

		var tempGasUsed uint64
		receipt, err := core.ApplyTransaction(chain.Config(), chain, &env.coinbase, gasPool, stateDB, env.header, tx, &tempGasUsed, *chain.GetVMConfig())
		if err != nil {
			return builderTypes.SimulatedBundle{}, err
		}
		if receipt.Status == types.ReceiptStatusFailed && !containsHash(bundle.RevertingTxHashes, receipt.TxHash) {
			return builderTypes.SimulatedBundle{}, errors.New("failed tx")
		}

		totalGasUsed += receipt.GasUsed

		coinbaseBalanceAfter := stateDB.GetBalance(env.coinbase)
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

func TestTxCommit(t *testing.T) {
	statedb, chain, signers := genTestSetup(GasLimit)

	env := newEnvironment(chain, statedb, signers.addresses[0], GasLimit, big.NewInt(1))
	envDiff := newEnvironmentDiff(env)

	tx := signers.signTx(1, 21000, big.NewInt(0), big.NewInt(1), signers.addresses[2], big.NewInt(0), []byte{})

	receipt, i, err := envDiff.commitTx(tx, chain)
	if err != nil {
		t.Fatal("can't commit transaction:", err)
	}
	if receipt.Status != 1 {
		t.Fatal("tx failed", receipt)
	}
	if i != shiftTx {
		t.Fatal("incorrect shift value")
	}

	if env.tcount != 0 {
		t.Fatal("env tcount modified")
	}
	if len(env.receipts) != 0 {
		t.Fatal("env receipts modified")
	}
	if len(env.txs) != 0 {
		t.Fatal("env txs modified")
	}
	if env.gasPool.Gas() != GasLimit {
		t.Fatal("env gas pool modified")
	}

	if envDiff.gasPool.AddGas(receipt.GasUsed).Gas() != GasLimit {
		t.Fatal("envDiff gas pool incorrect")
	}
	if envDiff.header.GasUsed != receipt.GasUsed {
		t.Fatal("envDiff gas used is incorrect")
	}
	if len(envDiff.newReceipts) != 1 {
		t.Fatal("envDiff receipts incorrect")
	}
	if len(envDiff.newTxs) != 1 {
		t.Fatal("envDiff txs incorrect")
	}
}

func TestBundleCommit(t *testing.T) {
	statedb, chain, signers := genTestSetup(GasLimit)

	env := newEnvironment(chain, statedb, signers.addresses[0], GasLimit, big.NewInt(1))
	envDiff := newEnvironmentDiff(env)

	tx1 := signers.signTx(1, 21000, big.NewInt(0), big.NewInt(1), signers.addresses[2], big.NewInt(0), []byte{})
	tx2 := signers.signTx(1, 21000, big.NewInt(0), big.NewInt(1), signers.addresses[2], big.NewInt(0), []byte{})

	bundle := builderTypes.MevBundle{
		Txs:         types.Transactions{tx1, tx2},
		BlockNumber: env.header.Number,
	}

	simBundle, err := simulateBundle(env, bundle, chain)
	if err != nil {
		t.Fatal("Failed to simulate bundle", err)
	}

	err = envDiff.commitBundle(&simBundle, chain, nil)
	if err != nil {
		t.Fatal("Failed to commit bundle", err)
	}

	if len(envDiff.newTxs) != 2 {
		t.Fatal("Incorrect new txs")
	}
	if len(envDiff.newReceipts) != 2 {
		t.Fatal("Incorrect receipts txs")
	}
	if envDiff.gasPool.AddGas(21000*2).Gas() != GasLimit {
		t.Fatal("Gas pool incorrect update")
	}
}

func TestErrorTxCommit(t *testing.T) {
	statedb, chain, signers := genTestSetup(GasLimit)

	env := newEnvironment(chain, statedb, signers.addresses[0], GasLimit, big.NewInt(1))
	envDiff := newEnvironmentDiff(env)

	signers.nonces[1] = 10
	tx := signers.signTx(1, 21000, big.NewInt(0), big.NewInt(1), signers.addresses[2], big.NewInt(0), []byte{})

	_, i, err := envDiff.commitTx(tx, chain)
	if err == nil {
		t.Fatal("committed incorrect transaction:", err)
	}
	if i != popTx {
		t.Fatal("incorrect shift value")
	}

	if envDiff.gasPool.Gas() != GasLimit {
		t.Fatal("envDiff gas pool incorrect")
	}
	if envDiff.header.GasUsed != 0 {
		t.Fatal("envDiff gas used incorrect")
	}
	if envDiff.profit.Sign() != 0 {
		t.Fatal("envDiff new profit incorrect")
	}
	if len(envDiff.newReceipts) != 0 {
		t.Fatal("envDiff receipts incorrect")
	}
	if len(envDiff.newTxs) != 0 {
		t.Fatal("envDiff txs incorrect")
	}
}

func TestCommitTxOverGasLimit(t *testing.T) {
	statedb, chain, signers := genTestSetup(GasLimit)

	env := newEnvironment(chain, statedb, signers.addresses[0], 21000, big.NewInt(1))
	envDiff := newEnvironmentDiff(env)

	tx1 := signers.signTx(1, 21000, big.NewInt(0), big.NewInt(1), signers.addresses[2], big.NewInt(0), []byte{})
	tx2 := signers.signTx(1, 21000, big.NewInt(0), big.NewInt(1), signers.addresses[2], big.NewInt(0), []byte{})

	receipt, i, err := envDiff.commitTx(tx1, chain)
	if err != nil {
		t.Fatal("can't commit transaction:", err)
	}
	if receipt.Status != 1 {
		t.Fatal("tx failed", receipt)
	}
	if i != shiftTx {
		t.Fatal("incorrect shift value")
	}

	if envDiff.gasPool.Gas() != 0 {
		t.Fatal("Env diff gas pool is not drained")
	}

	_, _, err = envDiff.commitTx(tx2, chain)
	require.Error(t, err, "committed tx over gas limit")
}

func TestErrorBundleCommit(t *testing.T) {
	statedb, chain, signers := genTestSetup(GasLimit)

	env := newEnvironment(chain, statedb, signers.addresses[0], 21000*2, big.NewInt(1))
	envDiff := newEnvironmentDiff(env)

	// This tx will be included before bundle so bundle will fail because of gas limit
	tx0 := signers.signTx(4, 21000, big.NewInt(0), big.NewInt(1), signers.addresses[2], big.NewInt(0), []byte{})

	tx1 := signers.signTx(1, 21000, big.NewInt(0), big.NewInt(1), signers.addresses[2], big.NewInt(0), []byte{})
	tx2 := signers.signTx(1, 21000, big.NewInt(0), big.NewInt(1), signers.addresses[2], big.NewInt(0), []byte{})

	bundle := builderTypes.MevBundle{
		Txs:         types.Transactions{tx1, tx2},
		BlockNumber: env.header.Number,
	}

	simBundle, err := simulateBundle(env, bundle, chain)
	if err != nil {
		t.Fatal("Failed to simulate bundle", err)
	}

	_, _, err = envDiff.commitTx(tx0, chain)
	if err != nil {
		t.Fatal("Failed to commit tx0", err)
	}

	gasPoolBefore := *envDiff.gasPool
	gasUsedBefore := envDiff.header.GasUsed
	newProfitBefore := new(uint256.Int).Set(envDiff.profit)
	balanceBefore := envDiff.state.GetBalance(signers.addresses[2])

	err = envDiff.commitBundle(&simBundle, chain, nil)
	if err == nil {
		t.Fatal("Committed failed bundle", err)
	}

	if *envDiff.gasPool != gasPoolBefore {
		t.Fatal("gasPool changed")
	}

	if envDiff.header.GasUsed != gasUsedBefore {
		t.Fatal("gasUsed changed")
	}

	balanceAfter := envDiff.state.GetBalance(signers.addresses[2])
	if balanceAfter.Cmp(balanceBefore) != 0 {
		t.Fatal("balance changed")
	}

	if envDiff.profit.Cmp(newProfitBefore) != 0 {
		t.Fatal("newProfit changed")
	}

	if len(envDiff.newTxs) != 1 {
		t.Fatal("Incorrect new txs")
	}
	if len(envDiff.newReceipts) != 1 {
		t.Fatal("Incorrect receipts txs")
	}
}
