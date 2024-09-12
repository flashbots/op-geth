package ethapi

import (
	"context"
	"errors"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rpc"
)

// PrivateTxBundleAPI offers an API for accepting bundled transactions
type PrivateTxBundleAPI struct {
	b Backend
}

// NewPrivateTxBundleAPI creates a new Tx Bundle API instance.
func NewPrivateTxBundleAPI(b Backend) *PrivateTxBundleAPI {
	return &PrivateTxBundleAPI{b}
}

// SendBundleArgs represents the arguments for a SendBundle call.
type SendBundleArgs struct {
	Txs               []hexutil.Bytes `json:"txs"`
	BlockNumber       rpc.BlockNumber `json:"blockNumber"`
	MinTimestamp      *uint64         `json:"minTimestamp"`
	MaxTimestamp      *uint64         `json:"maxTimestamp"`
	RevertingTxHashes []common.Hash   `json:"revertingTxHashes"`
}

type SendBundleResult struct {
	BundleHash common.Hash `json:"bundleHash"`
}

// SendBundle will add the signed transaction to the transaction pool.
// The sender is responsible for signing the transaction and using the correct nonce and ensuring validity
func (s *PrivateTxBundleAPI) SendBundle(ctx context.Context, args SendBundleArgs) (*SendBundleResult, error) {
	var txs types.Transactions
	if len(args.Txs) == 0 {
		return nil, errors.New("bundle missing txs")
	}
	if args.BlockNumber == 0 {
		return nil, errors.New("bundle missing blockNumber")
	}

	for _, encodedTx := range args.Txs {
		tx := new(types.Transaction)
		if err := tx.UnmarshalBinary(encodedTx); err != nil {
			return nil, err
		}
		txs = append(txs, tx)
	}

	var minTimestamp, maxTimestamp uint64
	if args.MinTimestamp != nil {
		minTimestamp = *args.MinTimestamp
	}
	if args.MaxTimestamp != nil {
		maxTimestamp = *args.MaxTimestamp
	}

	bundleHash, err := s.b.SendBundle(ctx, txs, args.BlockNumber, minTimestamp, maxTimestamp, args.RevertingTxHashes)
	if err != nil {
		return nil, err
	}
	return &SendBundleResult{BundleHash: bundleHash}, nil
}
