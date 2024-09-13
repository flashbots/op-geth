package types

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/holiman/uint256"
)

type MevBundle struct {
	Txs               types.Transactions
	BlockNumber       *big.Int
	MinTimestamp      uint64
	MaxTimestamp      uint64
	RevertingTxHashes []common.Hash
	Hash              common.Hash
}

func (b *MevBundle) RevertingHash(hash common.Hash) bool {
	for _, revHash := range b.RevertingTxHashes {
		if revHash == hash {
			return true
		}
	}
	return false
}

type SimulatedBundle struct {
	MevGasPrice    *uint256.Int
	TotalEth       *uint256.Int // total profit of the bundle
	TotalGasUsed   uint64
	OriginalBundle MevBundle
}
