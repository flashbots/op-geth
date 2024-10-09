package miner

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/misc"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/r3labs/sse"
	"go.opentelemetry.io/otel/attribute"
)

type ISSSink func(receipts types.Receipts)

type ISSBuilder struct {
	miner     *Miner
	issTime   time.Duration // TODO: Maybe add some config for this
	blockTime time.Duration

	sink []ISSSink

	// current execution context
	cancelFn context.CancelFunc

	pendingEnv     *environment
	pendingEnvLock sync.Mutex

	notifyCh chan struct{}
}

func NewISSBuilder(miner *Miner, issTime time.Duration, blockTime time.Duration) (*ISSBuilder, error) {
	// Ensure that issTime is lower than blockTime
	if issTime >= blockTime {
		return nil, fmt.Errorf("issTime must be lower than blockTime")
	}

	builder := &ISSBuilder{
		miner:     miner,
		issTime:   issTime,
		blockTime: blockTime,
		sink:      []ISSSink{},
		notifyCh:  make(chan struct{}),
	}
	return builder, nil
}

func (i *ISSBuilder) AddSink(sink ISSSink) *ISSBuilder {
	i.sink = append(i.sink, sink)
	return i
}

func (i *ISSBuilder) Build(ctx context.Context, args *BuildPayloadArgs) (*Payload, error) {
	// cancel any previous builds
	if i.cancelFn != nil {
		log.Info("Cancelling previous build")
		i.cancelFn()
	}

	payload := newPayload(nil, args.Id())
	payload.isISS = true

	ctx, cancelFn := context.WithCancel(ctx)
	i.cancelFn = cancelFn

	go func() {
		if err := i.buildPayload(ctx, payload, args); err != nil {
			payload.update(&newPayloadResult{err: err}, 0)
		}
	}()

	return payload, nil
}

var (
	seqPrivKey     *ecdsa.PrivateKey
	seqPrivKeyAddr common.Address
)

func init() {
	var err error
	// TODO: CLI argument
	seqPrivKey, err = crypto.HexToECDSA("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
	if err != nil {
		panic(fmt.Errorf("BUG: %v", err))
	}
	seqPrivKeyAddr = crypto.PubkeyToAddress(seqPrivKey.PublicKey)
	fmt.Printf("Seq priv key %s\n", seqPrivKeyAddr.Hex())
}

// very very conservative estimate. TODO: this might not be required anymore.
var timeToHash = 150 * time.Millisecond

func (i *ISSBuilder) buildPayload(ctx context.Context, payload *Payload, args *BuildPayloadArgs) error {
	subCtx, span := tracer.Start(ctx, "iss_builder.buildPayload")
	defer span.End()

	params := &generateParams{
		timestamp:   args.Timestamp,
		forceTime:   true,
		parentHash:  args.Parent,
		coinbase:    args.FeeRecipient,
		random:      args.Random,
		withdrawals: args.Withdrawals,
		beaconRoot:  args.BeaconRoot,
		noTxs:       false,
		txs:         args.Transactions,
		gasLimit:    args.GasLimit,
	}

	blockTime, err := i.miner.validateParams(params)
	if err != nil {
		return err
	}

	work, err := i.miner.prepareWork(params)
	if err != nil {
		return err
	}

	i.pendingEnvLock.Lock()
	i.pendingEnv = work
	i.pendingEnvLock.Unlock()

	log.Info("Building block", "number", work.header.Number, "time", blockTime)
	start := time.Now()

	// add attributes
	span.SetAttributes(attribute.Int64("number", work.header.Number.Int64()))

	if work.gasPool == nil {
		gasLimit := i.miner.config.EffectiveGasCeil
		if gasLimit == 0 || gasLimit > work.header.GasLimit {
			gasLimit = work.header.GasLimit
		}
		work.gasPool = new(core.GasPool).AddGas(gasLimit)
	}

	misc.EnsureCreate2Deployer(i.miner.chainConfig, work.header.Time, work.state)

	// Apply the op payload transactions
	for _, tx := range params.txs {
		work.state.SetTxContext(tx.Hash(), work.tcount)
		err = i.miner.commitTransaction(work, tx)
		if err != nil {
			return err
		}
		work.tcount++
	}

	// make an early valid block only with the deposit transactions.
	// this is useful in case op-node asks for a block early.
	// TODO: This workflow can be improved to avoid assembling the block and the payload twice.
	body := types.Body{Transactions: work.txs, Withdrawals: params.withdrawals}
	block, err := i.miner.engine.FinalizeAndAssemble(i.miner.chain, work.header, work.state, &body, work.receipts)
	if err != nil {
		return err
	}

	res := &newPayloadResult{
		block:    block,
		fees:     totalFees(block, work.receipts),
		sidecars: work.sidecars,
		stateDB:  work.state,
		receipts: work.receipts,
	}
	payload.update(res, time.Since(start))

	if args.NoTxPool {
		// the block we built with the deposit txns is enough.
		return nil
	}

	gasLimit := work.header.GasLimit
	gasPool := new(core.GasPool).AddGas(work.header.GasLimit)

	// initial estimation of how much gas to put on each batch
	gasPerBatch := work.header.GasLimit / 4

	// we are not including the time it takes to hash in the time to build the ISS batches
	blockBuildingTimeLeft := blockTime - timeToHash
	initialTime := time.Now()

	// work is your snapshot reference to the whole state being built
	for {
		// check if there is enough time left to make another chunk of the block
		// - is there enough gas?
		// - is there enough time?
		// We are going to keep some wiggle room of n milliseconds for hashing
		if gasPool.Gas() == 0 {
			break
		}
		if blockBuildingTimeLeft <= 0 {
			break
		}

		fbCtx, fbSpan := tracer.Start(subCtx, "inter-block")

		timeForBatch := i.issTime
		if blockBuildingTimeLeft < timeForBatch {
			timeForBatch = blockBuildingTimeLeft
		}

		now := time.Now()

		select {
		case <-payload.stop:
			return nil
		default:
		}

		{
			_, fillSpan := tracer.Start(fbCtx, "fillBatch")
			preTxn := len(work.txs)

			// I have to use both a context and the timer because I can't pass the context to fillTransactions
			// and I cannot use timer.C to know if the timer is over
			// TODO: Transport the interrupt to the fillTransactions into a context
			batchCtx, cancel := context.WithCancel(context.Background())
			interrupt := &atomic.Int32{}
			time.AfterFunc(timeForBatch, func() {
				cancel()
				interrupt.Store(commitInterruptTimeout)
			})

			{
				// Add the system transaction. It is an unrecoverable error. If the system
				// transaction is not there we cannot create the sub-block.
				ttxxnn := types.NewTx(&types.LegacyTx{
					Nonce:    work.state.GetNonce(seqPrivKeyAddr),
					To:       &seqPrivKeyAddr,
					GasPrice: work.header.BaseFee,
					Gas:      21000,
					Data:     []byte(""),
				})

				ttxxnn, err = types.SignTx(ttxxnn, work.signer, seqPrivKey)
				if err != nil {
					return err
				}
				if err := i.miner.commitTransaction(work, ttxxnn); err != nil {
					return err
				}
			}

			// we must override this because it is what fillTransactions uses to determine if it should keep filling
			// take the snapshot of the work here for each iteration
			work.header.GasLimit = gasPerBatch
			if err := i.miner.fillTransactions(interrupt, work); err != nil {
				if errors.Is(err, errBlockInterruptedByTimeout) {
					// If the error is a timeout, break out of the inner loop
					break
				} else {
					return err
				}
			}

			fillSpan.SetAttributes(attribute.Int("txns", len(work.txs)-preTxn))
			fillSpan.End()

			// wait for the timer to fire even if the bb ends sooner
			<-batchCtx.Done()
		}

		// check again if the context was cancelled, in that case exit early
		// since we do not want to relay more info.
		select {
		case <-payload.stop:
			return nil
		default:
		}

		// wait for the timer to fire even if the bb ends sooner
		blockBuildingTimeLeft -= time.Since(now)
		fbSpan.End()

		{
			// Seal the intermediate block
			body := types.Body{Transactions: work.txs, Withdrawals: params.withdrawals}
			work.header.GasLimit = gasLimit // replace to be inserted in the block
			block, err := i.miner.engine.FinalizeAndAssemble(i.miner.chain, work.header, work.state, &body, work.receipts)
			if err != nil {
				return err
			}

			// fmt.Printf("(%d) Time since %s %d %d %d %d %s\n", work.header.Number, block.Hash(), block.GasLimit(), block.GasUsed(), len(block.Transactions()), len(work.receipts), time.Since(now))

			res := &newPayloadResult{
				block:    block,
				fees:     totalFees(block, work.receipts),
				sidecars: work.sidecars,
				stateDB:  work.state,
				receipts: work.receipts,
			}
			payload.update(res, time.Since(initialTime))
		}

		for _, sink := range i.sink {
			sink(work.receipts)
		}

		// notify that a new batch is ready
		select {
		case i.notifyCh <- struct{}{}:
		default:
		}
	}

	return nil
}

func (i *ISSBuilder) PendingBlock() (*types.Block, types.Receipts, *state.StateDB) {
	i.pendingEnvLock.Lock()
	defer i.pendingEnvLock.Unlock()

	if i.pendingEnv == nil {
		return nil, nil, nil
	}

	block := &types.Block{}
	block.WithTransactions(i.pendingEnv.txs)

	return block, i.pendingEnv.receipts, i.pendingEnv.state.Copy()
}

func (i *ISSBuilder) AddSSEStream(port uint64) {
	eventStream := sse.New()
	eventStream.AutoReplay = false
	eventStream.CreateStream("iss")

	// Create a new Mux and set the handler
	mux := http.NewServeMux()
	mux.HandleFunc("/events", eventStream.HTTPHandler)

	sink := func(receipts types.Receipts) {
		raw, err := json.Marshal(receipts)
		if err != nil {
			panic(err)
		}

		eventStream.Publish("iss", &sse.Event{
			Data: raw,
		})
	}
	i.AddSink(sink)

	go http.ListenAndServe(fmt.Sprintf("0.0.0.0:%d", port), mux)
}
