package builder

import (
	builderTypes "github.com/ethereum/go-ethereum/builder/types"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/eth"
	"github.com/ethereum/go-ethereum/miner"
	"github.com/ethereum/go-ethereum/params"
)

type IEthereumService interface {
	BuildBlock(attrs *builderTypes.PayloadAttributes) (IPayload, error)
	GetBlockByHash(hash common.Hash) *types.Block
	Config() *params.ChainConfig
	Synced() bool
}

type EthereumService struct {
	eth *eth.Ethereum
	cfg *Config
}

func NewEthereumService(eth *eth.Ethereum, config *Config) *EthereumService {
	return &EthereumService{
		eth: eth,
		cfg: config,
	}
}

func (s *EthereumService) BuildBlock(attrs *builderTypes.PayloadAttributes) (IPayload, error) {
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

	return s.eth.Miner().BuildPayloadWithExtraData(args, attrs.ExtraData)
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
