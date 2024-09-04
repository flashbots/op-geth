package builder

import (
	"context"
	"errors"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/beacon/engine"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/eth"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/miner"
	"github.com/ethereum/go-ethereum/params"
)

type IEthereumService interface {
	BuildBlock(ctx context.Context, attrs *BuilderPayloadAttributes) (chan *SubmitBlockOpts, error)
	GetBlockByHash(hash common.Hash) *types.Block
	Config() *params.ChainConfig
	Synced() bool
}

type EthereumService struct {
	eth           *eth.Ethereum
	cfg           *Config
	retryInterval time.Duration
}

func NewEthereumService(eth *eth.Ethereum, config *Config) *EthereumService {
	return &EthereumService{
		eth:           eth,
		cfg:           config,
		retryInterval: 1 * time.Second,
	}
}

func (s *EthereumService) WithRetryInterval(retryInterval time.Duration) {
	s.retryInterval = retryInterval
}

func (s *EthereumService) BuildBlock(ctx context.Context, attrs *BuilderPayloadAttributes) (chan *SubmitBlockOpts, error) {
	resCh := make(chan *SubmitBlockOpts, 1)

	// The context already includes the timeout with the block time.
	// Submission queue for the given payload attributes
	// multiple jobs can run for different attributes fot the given slot
	// 1. When new block is ready we check if its profit is higher than profit of last best block
	//    if it is we set queueBest* to values of the new block and notify queueSignal channel.
	var (
		queueLastSubmittedHash common.Hash
		queueBestBlockValue    *big.Int = big.NewInt(0)
	)

	// retry build block every builderBlockRetryInterval
	go runRetryLoop(ctx, s.retryInterval, func() {
		log.Info("retrying BuildBlock",
			"slot", attrs.Slot,
			"parent", attrs.HeadHash,
			"retryInterval", s.retryInterval)

		payload, err := s.buildBlockImpl(attrs)
		if err != nil {
			log.Warn("Failed to build block", "err", err)
			return
		}

		sealedAt := time.Now()
		if payload.ExecutionPayload.BlockHash != queueLastSubmittedHash && payload.BlockValue.Cmp(queueBestBlockValue) >= 0 {
			queueLastSubmittedHash = payload.ExecutionPayload.BlockHash
			queueBestBlockValue = payload.BlockValue

			submitBlockOpts := SubmitBlockOpts{
				ExecutionPayloadEnvelope: payload,
				SealedAt:                 sealedAt,
				PayloadAttributes:        attrs,
			}
			resCh <- &submitBlockOpts
		}
	})

	return resCh, nil
}

func (s *EthereumService) buildBlockImpl(attrs *BuilderPayloadAttributes) (*engine.ExecutionPayloadEnvelope, error) {
	// Send a request to generate a full block in the background.
	// The result can be obtained via the returned channel.
	args := &miner.BuildPayloadArgs{
		Parent:       attrs.HeadHash,
		Timestamp:    uint64(attrs.Timestamp),
		FeeRecipient: attrs.SuggestedFeeRecipient, // TODO (builder): use builder key as fee recipient
		GasLimit:     &attrs.GasLimit,
		Random:       attrs.Random,
		Withdrawals:  attrs.Withdrawals,
		BeaconRoot:   attrs.ParentBeaconBlockRoot,
		Transactions: attrs.Transactions,
		NoTxPool:     attrs.NoTxPool,
	}

	payload, err := s.eth.Miner().BuildPayload(args)
	if err != nil {
		log.Error("Failed to build payload", "err", err)
		return nil, err
	}

	resCh := make(chan *engine.ExecutionPayloadEnvelope, 1)
	go func() {
		resCh <- payload.ResolveFull()
	}()

	timer := time.NewTimer(s.cfg.BlockTime)
	defer timer.Stop()

	select {
	case payload := <-resCh:
		if payload == nil {
			return nil, errors.New("received nil payload from sealing work")
		}
		return payload, nil
	case <-timer.C:
		payload.Cancel()
		log.Error("timeout waiting for block", "parent hash", attrs.HeadHash, "slot", attrs.Slot)
		return nil, errors.New("timeout waiting for block result")
	}
}

func (s *EthereumService) GetBlockByHash(hash common.Hash) *types.Block {
	return s.eth.BlockChain().GetBlockByHash(hash)
}

func (s *EthereumService) Config() *params.ChainConfig {
	return s.eth.BlockChain().Config()
}

func (s *EthereumService) Synced() bool {
	return s.eth.Synced()
}
