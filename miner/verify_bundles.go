package miner

import (
	"fmt"

	builderTypes "github.com/ethereum/go-ethereum/builder/types"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

// ErrBundleTxNotFound is returned when a tx is not found in the resulting block
type ErrBundleTxNotFound struct {
	BundleHash common.Hash
	TxHash     common.Hash
	// Index of the tx in the bundle
	TxIndex int
}

func NewErrBundleTxNotFound(bundleHash, txHash common.Hash, txIndex int) *ErrBundleTxNotFound {
	return &ErrBundleTxNotFound{
		BundleHash: bundleHash,
		TxHash:     txHash,
		TxIndex:    txIndex,
	}
}

func (e *ErrBundleTxNotFound) Error() string {
	return fmt.Sprintf("tx from included bundle not found tx_hash=%s, bundle_hash=%s, tx_bundle_index=%d", e.TxHash.Hex(), e.BundleHash.Hex(), e.TxIndex)
}

// ErrBundleTxReverted is returned when a tx is reverted in the resulting block, but it was not allowed to be reverted
type ErrBundleTxReverted struct {
	BundleHash common.Hash
	TxHash     common.Hash
	// Index of the tx in the bundle
	TxIndex int
}

func NewErrBundleTxReverted(bundleHash, txHash common.Hash, txIndex int) *ErrBundleTxReverted {
	return &ErrBundleTxReverted{
		BundleHash: bundleHash,
		TxHash:     txHash,
		TxIndex:    txIndex,
	}
}

func (e *ErrBundleTxReverted) Error() string {
	return fmt.Sprintf("tx from included bundle reverted tx_hash=%s, bundle_hash=%s, tx_bundle_index=%d", e.TxHash.Hex(), e.BundleHash.Hex(), e.TxIndex)
}

// ErrBundleTxWrongPlace is returned when a tx is found in the resulting block, but it is not in the right place
type ErrBundleTxWrongPlace struct {
	BundleHash common.Hash
	TxHash     common.Hash
	// Index of the tx in the bundle
	TxIndex int
	// Index of the tx in the block
	BlockIndex         int
	ExpectedBlockIndex int
}

func NewErrBundleTxWrongPlace(bundleHash, txHash common.Hash, txIndex, blockIndex, expectedBlockIndex int) *ErrBundleTxWrongPlace {
	return &ErrBundleTxWrongPlace{
		BundleHash:         bundleHash,
		TxHash:             txHash,
		TxIndex:            txIndex,
		BlockIndex:         blockIndex,
		ExpectedBlockIndex: expectedBlockIndex,
	}
}

func (e *ErrBundleTxWrongPlace) Error() string {
	return fmt.Sprintf("tx from included bundle is in wrong place tx_hash=%s, bundle_hash=%s, tx_bundle_index=%d, tx_block_index=%d, expected_block_index=%d", e.TxHash.Hex(), e.BundleHash.Hex(), e.TxIndex, e.BlockIndex, e.ExpectedBlockIndex)
}

// ErrPrivateTxFromFailedBundle is returned when a private tx is included in the block, but the bundle it belongs to was not included
type ErrPrivateTxFromFailedBundle struct {
	BundleHash common.Hash
	TxHash     common.Hash
	// Index of the tx in the bundle
	TxIndex int
}

func NewErrPrivateTxFromFailedBundle(bundleHash, txHash common.Hash, txIndex int) *ErrPrivateTxFromFailedBundle {
	return &ErrPrivateTxFromFailedBundle{
		BundleHash: bundleHash,
		TxHash:     txHash,
		TxIndex:    txIndex,
	}
}

func (e *ErrPrivateTxFromFailedBundle) Error() string {
	return fmt.Sprintf("private tx from failed bundle included in the block tx_hash=%s, bundle_hash=%s, tx_bundle_index=%d", e.TxHash.Hex(), e.BundleHash.Hex(), e.TxIndex)
}

// ErrForcedTxNotIncluded is returned when a forced tx is not included in the block
type ErrForcedTxNotIncluded struct {
	TxHash common.Hash
}

func NewErrForcedTxNotIncluded(txHash common.Hash) *ErrForcedTxNotIncluded {
	return &ErrForcedTxNotIncluded{
		TxHash: txHash,
	}
}

func (e *ErrForcedTxNotIncluded) Error() string {
	return fmt.Sprintf("forced tx not included in the block tx_hash=%s", e.TxHash.Hex())
}

// ErrForcedTxReverted is returned when a forced tx is reverted in the block, but it was not allowed to be reverted
type ErrForcedTxReverted struct {
	TxHash  common.Hash
	TxIndex int
}

func NewErrForcedTxReverted(txHash common.Hash, txIndex int) *ErrForcedTxReverted {
	return &ErrForcedTxReverted{
		TxHash:  txHash,
		TxIndex: txIndex,
	}
}

func (e *ErrForcedTxReverted) Error() string {
	return fmt.Sprintf("forced tx reverted tx_hash=%s, tx_index=%d", e.TxHash.Hex(), e.TxIndex)
}

// ErrForcedTxWrongPlace is returned when a forced tx is found in the block, but it is not in the right place
type ErrForcedTxWrongPlace struct {
	TxHash             common.Hash
	TxIndex            int
	ExpectedBlockIndex int
}

func NewErrForcedTxWrongPlace(txHash common.Hash, txIndex, expectedBlockIndex int) *ErrForcedTxWrongPlace {
	return &ErrForcedTxWrongPlace{
		TxHash:             txHash,
		TxIndex:            txIndex,
		ExpectedBlockIndex: expectedBlockIndex,
	}
}

func (e *ErrForcedTxWrongPlace) Error() string {
	return fmt.Sprintf("forced tx is in wrong place tx_hash=%s, tx_index=%d, expected_block_index=%d", e.TxHash.Hex(), e.TxIndex, e.ExpectedBlockIndex)
}

// ErrUnexpectedTx is returned when a tx is included in the block, but it is not from the mempool or from the included bundles
// ErrUnexpectedTx is returned when a tx is included in the block, but it is not from the mempool or from the included bundles
type ErrUnexpectedTx struct {
	TxHash common.Hash
}

func NewErrUnexpectedTx(txHash common.Hash) *ErrUnexpectedTx {
	return &ErrUnexpectedTx{
		TxHash: txHash,
	}
}

func (e *ErrUnexpectedTx) Error() string {
	return fmt.Sprintf("unexpected tx included in the block tx_hash=%s", e.TxHash.Hex())
}

// VerifyBundlesAtomicity checks that all txs from the included bundles are included in the block correctly
// 1. We check that all non-reverted txs from the bundle are included in the block and are not reverted
// 2. Reverted txs are allowed to be not included in the block
// 3. All txs from the bundle must be in the right order, gaps between txs are allowed
// 4. All txs in the block are either from mempool or from the included bundles
func VerifyBundlesAtomicity(env *environment, committedBundles, allBundles []builderTypes.SimulatedBundle, mempoolTxHashes map[common.Hash]struct{}, forcedTxs types.Transactions) error {
	// bundleHash -> tx
	includedBundles := make(bundleHashToTransactionDataMap).ExtractFromBundles(committedBundles)

	includedTxDataByHash := extractIncludedTxDataFromEnv(env)

	allUsedBundles := make(bundleHashToTransactionDataMap).ExtractFromBundles(allBundles)

	forcedTxHashes := make(forcedTxHashesMap).ExtractFromTxs(forcedTxs)

	privateTxDataFromFailedBundles := extractPrivateTxsFromFailedBundles(includedBundles, allUsedBundles, mempoolTxHashes)

	return checkBundlesAtomicity(includedBundles, includedTxDataByHash, privateTxDataFromFailedBundles, mempoolTxHashes, forcedTxHashes)
}

type bundleTxData struct {
	hash      common.Hash
	canRevert bool
}

type includedTxData struct {
	hash     common.Hash
	index    int
	reverted bool
}

type privateTxData struct {
	bundleHash common.Hash
	index      int
}

type forcedTxData struct {
	hash  common.Hash
	index int
}

type bundleHashToTransactionDataMap map[common.Hash][]bundleTxData

type forcedTxHashesMap map[common.Hash]forcedTxData

func (btm bundleHashToTransactionDataMap) ExtractFromBundles(bundles []builderTypes.SimulatedBundle) bundleHashToTransactionDataMap {
	for _, b := range bundles {
		bundleData := make([]bundleTxData, len(b.OriginalBundle.Txs))
		for i, tx := range b.OriginalBundle.Txs {
			bundleData[i] = bundleTxData{
				hash:      tx.Hash(),
				canRevert: b.OriginalBundle.RevertingHash(tx.Hash()),
			}
		}

		btm[b.OriginalBundle.Hash] = bundleData
	}
	return btm
}

func (mth forcedTxHashesMap) ExtractFromTxs(txs types.Transactions) forcedTxHashesMap {
	for i, tx := range txs {
		mth[tx.Hash()] = forcedTxData{
			hash:  tx.Hash(),
			index: i,
		}
	}
	return mth
}

// checkBundlesAtomicity checks that all txs from the included bundles are included in the block correctly
func checkBundlesAtomicity(
	includedBundles map[common.Hash][]bundleTxData,
	includedTxDataByHash map[common.Hash]includedTxData,
	privateTxsFromFailedBundles map[common.Hash]privateTxData,
	mempoolTxHashes map[common.Hash]struct{},
	forcedTxHashes map[common.Hash]forcedTxData,
) error {
	txsFromSuccessfulBundles := make(map[common.Hash]struct{})

	for txHash, tx := range forcedTxHashes {
		// must be at top of the block and not reverted
		if txInclusion, ok := includedTxDataByHash[txHash]; !ok {
			return NewErrForcedTxNotIncluded(txHash)
		} else if txInclusion.reverted {
			return NewErrForcedTxReverted(txHash, txInclusion.index)
		} else if txInclusion.index != tx.index {
			return NewErrForcedTxWrongPlace(txHash, txInclusion.index, tx.index)
		}
	}

	for bundleHash, b := range includedBundles {
		var (
			firstTxBlockIdx  int
			firstTxBundleIdx int
			firstTxFound     = false
		)
		// 1. locate the first included tx of the bundle
		for bundleIdx, tx := range b {
			txsFromSuccessfulBundles[tx.hash] = struct{}{}

			txInclusion, ok := includedTxDataByHash[tx.hash]
			if !ok {
				// tx not found, maybe it was reverting
				if tx.canRevert {
					continue
				} else {
					return NewErrBundleTxNotFound(bundleHash, tx.hash, bundleIdx)
				}
			}

			if txInclusion.reverted && !tx.canRevert {
				return NewErrBundleTxReverted(bundleHash, tx.hash, bundleIdx)
			}

			// optional txs can be outside the bundle, so we don't use them to determine ordering of the bundle
			if tx.canRevert {
				continue
			}

			firstTxBlockIdx = txInclusion.index
			firstTxBundleIdx = bundleIdx
			firstTxFound = true
			break
		}

		// none of the txs from the bundle are included
		if !firstTxFound {
			continue
		}

		currentBlockTx := firstTxBlockIdx + 1
		// locate other txs in the bundle
		for idx, tx := range b[firstTxBundleIdx+1:] {
			txsFromSuccessfulBundles[tx.hash] = struct{}{}

			bundleIdx := firstTxBundleIdx + 1 + idx
			// see if tx is on its place
			txInclusion, ok := includedTxDataByHash[tx.hash]
			if !ok {
				// tx was not found, maybe its reverting
				if tx.canRevert {
					continue
				} else {
					return NewErrBundleTxNotFound(bundleHash, tx.hash, bundleIdx)
				}
			}

			if txInclusion.reverted && !tx.canRevert {
				return NewErrBundleTxReverted(bundleHash, tx.hash, bundleIdx)
			}

			// we don't do position check for optional txs
			if tx.canRevert {
				continue
			}

			// we allow gaps between txs in the bundle,
			// but txs must be in the right order
			if txInclusion.index < currentBlockTx {
				return NewErrBundleTxWrongPlace(bundleHash, tx.hash, bundleIdx, txInclusion.index, currentBlockTx)
			}

			currentBlockTx = txInclusion.index + 1
		}
	}

	for hash, priv := range privateTxsFromFailedBundles {
		if _, ok := txsFromSuccessfulBundles[hash]; ok {
			continue
		}
		if _, ok := includedTxDataByHash[hash]; ok {
			return NewErrPrivateTxFromFailedBundle(priv.bundleHash, hash, priv.index)
		}
	}

	for hash := range includedTxDataByHash {
		if _, ok := txsFromSuccessfulBundles[hash]; ok {
			continue
		}
		if _, ok := mempoolTxHashes[hash]; ok {
			continue
		}
		if _, ok := forcedTxHashes[hash]; ok {
			continue
		}
		return NewErrUnexpectedTx(hash)
	}

	return nil
}

func extractBundleTxDataFromBundles(bundles []builderTypes.SimulatedBundle, result map[common.Hash][]bundleTxData) {
	for _, b := range bundles {
		bundleData := make([]bundleTxData, len(b.OriginalBundle.Txs))
		for i, tx := range b.OriginalBundle.Txs {
			bundleData[i] = bundleTxData{
				hash:      tx.Hash(),
				canRevert: b.OriginalBundle.RevertingHash(tx.Hash()),
			}
		}
		result[b.OriginalBundle.Hash] = bundleData
	}
}

func extractIncludedTxDataFromEnv(env *environment) map[common.Hash]includedTxData {
	res := make(map[common.Hash]includedTxData)
	for i, tx := range env.txs {
		if tx != nil {
			res[tx.Hash()] = includedTxData{
				hash:     tx.Hash(),
				index:    i,
				reverted: env.receipts[i].Status == types.ReceiptStatusFailed,
			}
		}
	}
	return res
}

func extractPrivateTxsFromFailedBundles(
	includedBundles, allBundles map[common.Hash][]bundleTxData, mempoolTxHashes map[common.Hash]struct{},
) map[common.Hash]privateTxData {
	// we don't handle overlapping bundles here, they are handled in checkBundlesAtomicity
	res := make(map[common.Hash]privateTxData)

	for bundleHash, b := range allBundles {
		if _, bundleIncluded := includedBundles[bundleHash]; bundleIncluded {
			continue
		}

		for i, tx := range b {
			if _, mempool := mempoolTxHashes[tx.hash]; mempool {
				continue
			}
			res[tx.hash] = privateTxData{
				bundleHash: bundleHash,
				index:      i,
			}
		}
	}
	return res
}
