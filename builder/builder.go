package builder

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	_ "os"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/beacon/engine"
	builderTypes "github.com/ethereum/go-ethereum/builder/types"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/holiman/uint256"
)

var (
	ErrIncorrectSlot         = errors.New("incorrect slot")
	ErrNoPayloads            = errors.New("no payloads")
	ErrSlotFromPayload       = errors.New("could not get slot from payload")
	ErrSlotMismatch          = errors.New("slot mismatch")
	ErrParentHashFromPayload = errors.New("could not get parent hash from payload")
	ErrParentHashMismatch    = errors.New("parent hash mismatch")
)

type IBuilder interface {
	GetPayload(request *builderTypes.BuilderPayloadRequest) (*builderTypes.VersionedBuilderPayloadResponse, error)
	Start() error
	Stop() error

	handleGetPayload(w http.ResponseWriter, req *http.Request)
}

type IPayload interface {
	ResolveFull() *engine.ExecutionPayloadEnvelope
}

type Builder struct {
	eth                         IEthereumService
	ignoreLatePayloadAttributes bool
	beaconClient                IBeaconClient
	builderPrivateKey           *ecdsa.PrivateKey
	builderAddress              common.Address

	builderBlockTime time.Duration

	proposerAddress common.Address

	slotMu        sync.Mutex
	slotAttrs     builderTypes.PayloadAttributes
	slotCtx       context.Context
	slotCtxCancel context.CancelFunc

	payloadMu sync.Mutex
	payload   IPayload

	stop chan struct{}
}

// BuilderArgs is a struct that contains all the arguments needed to create a new Builder
type BuilderArgs struct {
	builderPrivateKey           *ecdsa.PrivateKey
	builderAddress              common.Address
	proposerAddress             common.Address
	blockTime                   time.Duration
	eth                         IEthereumService
	ignoreLatePayloadAttributes bool
	beaconClient                IBeaconClient
}

func NewBuilder(args BuilderArgs) (*Builder, error) {
	slotCtx, slotCtxCancel := context.WithCancel(context.Background())
	return &Builder{
		eth:                         args.eth,
		ignoreLatePayloadAttributes: args.ignoreLatePayloadAttributes,
		beaconClient:                args.beaconClient,
		builderPrivateKey:           args.builderPrivateKey,
		builderAddress:              args.builderAddress,
		proposerAddress:             args.proposerAddress,
		builderBlockTime:            args.blockTime,

		slotCtx:       slotCtx,
		slotCtxCancel: slotCtxCancel,

		stop: make(chan struct{}, 1),
	}, nil
}

func (b *Builder) Start() error {
	log.Info("Starting builder")
	// Start regular payload attributes updates
	go func() {
		c := make(chan builderTypes.PayloadAttributes)
		go b.beaconClient.SubscribeToPayloadAttributesEvents(c)

		currentSlot := uint64(0)

		for {
			select {
			case <-b.stop:
				return
			case payloadAttributes := <-c:
				log.Info("Received payload attributes", "slot", payloadAttributes.Slot, "hash", payloadAttributes.HeadHash.String())
				// Right now we are building only on a single head. This might change in the future!
				if payloadAttributes.Slot < currentSlot {
					continue
				} else if payloadAttributes.Slot == currentSlot {
					// Subsequent sse events should only be canonical!
					if !b.ignoreLatePayloadAttributes {
						err := b.handlePayloadAttributes(&payloadAttributes)
						if err != nil {
							log.Error("error with builder processing on payload attribute",
								"latestSlot", currentSlot,
								"processedSlot", payloadAttributes.Slot,
								"headHash", payloadAttributes.HeadHash.String(),
								"error", err)
						}
					}
				} else if payloadAttributes.Slot > currentSlot {
					currentSlot = payloadAttributes.Slot
					err := b.handlePayloadAttributes(&payloadAttributes)
					if err != nil {
						log.Error("error with builder processing on payload attribute",
							"latestSlot", currentSlot,
							"processedSlot", payloadAttributes.Slot,
							"headHash", payloadAttributes.HeadHash.String(),
							"error", err)
					}
				}
			}
		}
	}()

	return b.beaconClient.Start()
}

func (b *Builder) Stop() error {
	close(b.stop)
	return nil
}

func (b *Builder) GetPayload(request *builderTypes.BuilderPayloadRequest) (*builderTypes.VersionedBuilderPayloadResponse, error) {
	if request == nil {
		return nil, errors.New("request is nil")
	}

	log.Info("received get payload request", "slot", request.Message.Slot, "parent", request.Message.ParentHash)

	// verify proposer signature
	if b.proposerAddress != (common.Address{}) {
		err := b.verifyProposerSignature(request)
		if err != nil {
			log.Warn("proposer signature verification failed", "err", err)
			return nil, fmt.Errorf("proposer signature verification failed: %w", err)
		}
	}

	bestBlock, err := b.getVersionedBlockSubmission(request.Message.Slot, request.Message.ParentHash)
	if err != nil {
		log.Warn("error getting versioned block submission", "err", err)
		return nil, fmt.Errorf("error getting builder block: %w", err)
	}

	if bestBlock.Message.Slot != request.Message.Slot {
		log.Warn("slot not equal", "requested", request.Message.Slot, "block", bestBlock.Message.Slot)
		return nil, ErrSlotMismatch
	}

	if bestBlock.Message.ParentHash != request.Message.ParentHash {
		log.Warn("parent hash not equal", "requested", request.Message.ParentHash, "block", bestBlock.Message.ParentHash.String())
		return nil, ErrParentHashMismatch
	}

	log.Info("payload delivered", "hash", bestBlock.Message.BlockHash.String())

	return bestBlock, nil
}

func (b *Builder) verifyProposerSignature(payload *builderTypes.BuilderPayloadRequest) error {
	msg, err := rlp.EncodeToBytes(payload.Message)
	if err != nil {
		return fmt.Errorf("could not encode message, %w", err)
	}
	signingHash, err := BuilderSigningHash(b.eth.Config(), msg)
	if err != nil {
		return fmt.Errorf("could not get signing hash, %w", err)
	}
	recoveredPubkey, err := crypto.SigToPub(signingHash[:], payload.Signature)
	if err != nil {
		return fmt.Errorf("could not recover pubkey, %w", err)
	}
	recoveredAddress := crypto.PubkeyToAddress(*recoveredPubkey)
	if recoveredAddress != b.proposerAddress {
		return fmt.Errorf("recovered address does not match proposer address, %s != %s", recoveredAddress, b.proposerAddress)
	}
	return nil
}

func (b *Builder) handleGetPayload(w http.ResponseWriter, req *http.Request) {
	start := time.Now()
	success := false

	defer func() {
		// Collect metrics at end of request
		updateServeTimeHistogram("getPayload", success, time.Since(start))
	}()

	// Read the body first, so we can decode it later
	body, err := io.ReadAll(req.Body)
	if err != nil {
		if strings.Contains(err.Error(), "i/o timeout") {
			log.Error("getPayload request failed to decode (i/o timeout)", "err", err)
			respondError(w, http.StatusInternalServerError, err.Error())
			return
		}

		log.Error("could not read body of request from the op node", "err", err)
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Decode payload
	payload := new(builderTypes.BuilderPayloadRequest)
	if err := json.NewDecoder(bytes.NewReader(body)).Decode(payload); err != nil {
		log.Warn("failed to decode getPayload request", "err", err)
		respondError(w, http.StatusBadRequest, "failed to decode payload")
		return
	}

	log.Info("received handle get payload request", "slot", payload.Message.Slot, "parent", payload.Message.ParentHash.String())

	bestSubmission, err := b.GetPayload(payload)
	if err != nil {
		handleError(w, err)
		updateServeTimeHistogram("getPayload", false, time.Since(start))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(bestSubmission); err != nil {
		updateServeTimeHistogram("getPayload", false, time.Since(start))
		log.Error("could not encode response", "err", err)
		respondError(w, http.StatusInternalServerError, "could not encode response")
		return
	}
	updateServeTimeHistogram("getPayload", true, time.Since(start))
}

func (b *Builder) getVersionedBlockSubmission(slot uint64, parentHash common.Hash) (*builderTypes.VersionedBuilderPayloadResponse, error) {
	var executionPayloadEnvelope *engine.ExecutionPayloadEnvelope
	b.payloadMu.Lock()
	if b.payload != nil {
		executionPayloadEnvelope = b.payload.ResolveFull()
	}
	b.payloadMu.Unlock()

	if executionPayloadEnvelope == nil {
		return nil, fmt.Errorf("no builder block found")
	}

	executionPayload := executionPayloadEnvelope.ExecutionPayload

	log.Info(
		"saveBlockSubmission",
		"slot", slot,
		"parent", parentHash.String(),
		"hash", executionPayload.BlockHash.String(),
	)

	var dataVersion builderTypes.SpecVersion
	if b.eth.Config().IsEcotone(executionPayload.Timestamp) {
		dataVersion = builderTypes.SpecVersionBedrock
	} else if b.eth.Config().IsCanyon(executionPayload.Timestamp) {
		dataVersion = builderTypes.SpecVersionCanyon
	} else {
		dataVersion = builderTypes.SpecVersionEcotone
	}

	value, overflow := uint256.FromBig(executionPayloadEnvelope.BlockValue)
	if overflow {
		return nil, fmt.Errorf("could not set block value due to value overflow")
	}

	blockBidMsg := builderTypes.BidTrace{
		Slot:                 slot,
		ParentHash:           executionPayload.ParentHash,
		BlockHash:            executionPayload.BlockHash,
		BuilderAddress:       b.builderAddress,
		ProposerAddress:      b.proposerAddress,
		ProposerFeeRecipient: executionPayload.FeeRecipient,
		GasLimit:             executionPayload.GasLimit,
		GasUsed:              executionPayload.GasUsed,
		Value:                value.ToBig(),
	}

	signature, err := b.signBuilderBid(&blockBidMsg)
	if err != nil {
		return nil, fmt.Errorf("could not sign block bid message, %w", err)
	}

	versionedBlockRequest := &builderTypes.VersionedBuilderPayloadResponse{
		Version:          dataVersion,
		Message:          &blockBidMsg,
		ExecutionPayload: executionPayload,
		Signature:        signature,
	}

	log.Info("resolved block", "version", dataVersion.String(), "slot", slot, "value", executionPayloadEnvelope.BlockValue,
		"parent", executionPayload.ParentHash.String(), "hash", executionPayload.BlockHash)

	return versionedBlockRequest, nil
}

func (b *Builder) signBuilderBid(bid *builderTypes.BidTrace) ([]byte, error) {
	bidBytes, err := rlp.EncodeToBytes(bid)
	if err != nil {
		return nil, err
	}

	cfg := b.eth.Config()
	hash, err := BuilderSigningHash(cfg, bidBytes)
	if err != nil {
		return nil, err
	}

	return crypto.Sign(hash[:], b.builderPrivateKey)
}

func (b *Builder) handlePayloadAttributes(attrs *builderTypes.PayloadAttributes) error {
	if attrs == nil {
		return nil
	}

	log.Info("handling payload attribute", "slot", attrs.Slot, "hash", attrs.HeadHash)

	parentBlock := b.eth.GetBlockByHash(attrs.HeadHash)
	if parentBlock == nil {
		return fmt.Errorf("parent block hash not found in block tree given head block hash %s", attrs.HeadHash)
	}

	if !b.eth.Synced() {
		return errors.New("backend not Synced")
	}

	b.slotMu.Lock()
	defer b.slotMu.Unlock()

	if attrs.Equal(&b.slotAttrs) {
		log.Debug("ignoring known payload attribute", "slot", attrs.Slot, "hash", attrs.HeadHash)
		return nil
	}

	if b.slotCtxCancel != nil {
		b.slotCtxCancel()
	}

	slotCtx, slotCtxCancel := context.WithTimeout(context.Background(), b.builderBlockTime)
	b.slotAttrs = *attrs
	b.slotCtx = slotCtx
	b.slotCtxCancel = slotCtxCancel

	go b.runBuildingJob(b.slotCtx, attrs)
	return nil
}

func (b *Builder) runBuildingJob(slotCtx context.Context, attrs *builderTypes.PayloadAttributes) {
	log.Info("runBuildingJob", "slot", attrs.Slot, "parent", attrs.HeadHash, "payloadTimestamp", uint64(attrs.Timestamp), "txs", attrs.Transactions)

	payload, err := b.eth.BuildBlock(attrs)
	if err != nil {
		log.Warn("Failed to build block", "err", err)
		return
	}
	b.payloadMu.Lock()
	b.payload = payload
	b.payloadMu.Unlock()
}
