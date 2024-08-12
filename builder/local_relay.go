package builder

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"strconv"
	"sync"

	builderSpec "github.com/attestantio/go-builder-client/spec"
	consensusspec "github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/deneb"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	eth2UtilBellatrix "github.com/attestantio/go-eth2-client/util/bellatrix"
	eth2UtilCapella "github.com/attestantio/go-eth2-client/util/capella"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/log"
	"github.com/flashbots/go-boost-utils/bls"
	"github.com/flashbots/go-boost-utils/utils"
	"github.com/gorilla/mux"
)

// TODO (deneb): remove local relay

type ForkData struct {
	GenesisForkVersion    string
	BellatrixForkVersion  string
	GenesisValidatorsRoot string
}

type FullValidatorData struct {
	ValidatorData
	Timestamp uint64
}

type LocalRelay struct {
	beaconClient IBeaconClient

	relaySecretKey        *bls.SecretKey
	relayPublicKey        phase0.BLSPubKey
	serializedRelayPubkey hexutil.Bytes

	builderSigningDomain  phase0.Domain
	proposerSigningDomain phase0.Domain

	validatorsLock sync.RWMutex
	validators     map[PubkeyHex]FullValidatorData

	enableBeaconChecks bool

	bestDataLock   sync.Mutex
	bestHeader     *deneb.ExecutionPayloadHeader
	bestSubmission *builderSpec.VersionedSubmitBlockRequest

	indexTemplate *template.Template
	fd            ForkData
}

func NewLocalRelay(sk *bls.SecretKey, beaconClient IBeaconClient, builderSigningDomain, proposerSigningDomain phase0.Domain, fd ForkData, enableBeaconChecks bool) (*LocalRelay, error) {
	blsPk, err := bls.PublicKeyFromSecretKey(sk)
	if err != nil {
		return nil, err
	}
	pk, err := utils.BlsPublicKeyToPublicKey(blsPk)
	if err != nil {
		return nil, err
	}

	indexTemplate, err := parseIndexTemplate()
	if err != nil {
		log.Error("could not parse index template", "err", err)
		indexTemplate = nil
	}

	return &LocalRelay{
		beaconClient: beaconClient,

		relaySecretKey: sk,
		relayPublicKey: pk,

		builderSigningDomain:  builderSigningDomain,
		proposerSigningDomain: proposerSigningDomain,
		serializedRelayPubkey: bls.PublicKeyToBytes(blsPk),

		validators: make(map[PubkeyHex]FullValidatorData),

		enableBeaconChecks: enableBeaconChecks,

		indexTemplate: indexTemplate,
		fd:            fd,
	}, nil
}

func (r *LocalRelay) Start() error {
	r.beaconClient.Start()
	return nil
}

func (r *LocalRelay) Stop() {
	r.beaconClient.Stop()
}

func (r *LocalRelay) SubmitBlock(msg *builderSpec.VersionedSubmitBlockRequest, _ ValidatorData) error {
	if msg.Version != consensusspec.DataVersionDeneb {
		return fmt.Errorf("unsupported data version %d", msg.Version)
	}

	log.Info("submitting block to local relay", "msg", msg, "version", msg.Version)
	header, err := PayloadToPayloadHeader(msg.Deneb.ExecutionPayload)
	if err != nil {
		log.Error("could not convert payload to header", "err", err)
		return err
	}

	r.bestDataLock.Lock()
	r.bestSubmission = msg
	r.bestHeader = header
	r.bestDataLock.Unlock()

	return nil
}

func (r *LocalRelay) Config() RelayConfig {
	// local relay does not need config as it is submitting to its own internal endpoint
	return RelayConfig{}
}

func (r *LocalRelay) handleRegisterValidator(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
}

func (r *LocalRelay) GetValidatorForSlot(nextSlot uint64) (ValidatorData, error) {
	// Not implemented.
	return ValidatorData{}, errors.New("missing validator")
}

func (r *LocalRelay) handleGetHeader(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
}

func (r *LocalRelay) handleGetPayload(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
}

func (r *LocalRelay) handleGetPayloadTrusted(w http.ResponseWriter, req *http.Request) {
	// TODO: check api
	vars := mux.Vars(req)
	slot, err := strconv.Atoi(vars["slot"])
	if err != nil {
		respondError(w, http.StatusBadRequest, "incorrect slot")
		return
	}
	parentHashHex := vars["parent_hash"]

	r.bestDataLock.Lock()
	bestHeader := r.bestHeader
	bestSubmission := r.bestSubmission
	r.bestDataLock.Unlock()

	log.Info("Received unblinded(trusted) block request", "bestHeader", bestHeader, "bestSubmission", bestSubmission)

	if bestHeader == nil || bestSubmission == nil {
		log.Error("no builder submissions")
		respondError(w, http.StatusInternalServerError, "no payloads")
		return
	}

	if bestHeader.BlockNumber != uint64(slot) {
		log.Error("slot not equal", "requested", slot, "best", bestHeader.BlockNumber)
		respondError(w, http.StatusBadRequest, fmt.Sprintf("slot not equal requested: %d bestPayload: %d", slot, bestHeader.BlockNumber))
		return
	}

	if bestHeader.ParentHash.String() != parentHashHex {
		log.Error("parent hash not equal", "requested", parentHashHex, "best", bestHeader.ParentHash.String())
		respondError(w, http.StatusBadRequest, fmt.Sprintf("parent hash not equal requested: %s bestPayload: %s", parentHashHex, bestHeader.ParentHash.String()))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(bestSubmission); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log.Error("could not encode response", "err", err)
		respondError(w, http.StatusInternalServerError, "internal server error")
		return
	}
}

func (r *LocalRelay) handleIndex(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
}

type httpErrorResp struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func respondError(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(httpErrorResp{code, message}); err != nil {
		http.Error(w, message, code)
	}
}

func (r *LocalRelay) handleStatus(w http.ResponseWriter, req *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func ExecutionPayloadHeaderEqual(l, r *deneb.ExecutionPayloadHeader) bool {
	return l.ParentHash == r.ParentHash && l.FeeRecipient == r.FeeRecipient && l.StateRoot == r.StateRoot && l.ReceiptsRoot == r.ReceiptsRoot && l.LogsBloom == r.LogsBloom && l.PrevRandao == r.PrevRandao && l.BlockNumber == r.BlockNumber && l.GasLimit == r.GasLimit && l.GasUsed == r.GasUsed && l.Timestamp == r.Timestamp && l.BaseFeePerGas == r.BaseFeePerGas && bytes.Equal(l.ExtraData, r.ExtraData) && l.BlockHash == r.BlockHash && l.TransactionsRoot == r.TransactionsRoot && l.WithdrawalsRoot == r.WithdrawalsRoot && l.BlobGasUsed == r.BlobGasUsed && l.ExcessBlobGas == r.ExcessBlobGas
}

// PayloadToPayloadHeader converts an ExecutionPayload to ExecutionPayloadHeader
func PayloadToPayloadHeader(p *deneb.ExecutionPayload) (*deneb.ExecutionPayloadHeader, error) {
	if p == nil {
		return nil, errors.New("nil payload")
	}

	var txs []bellatrix.Transaction
	txs = append(txs, p.Transactions...)

	transactions := eth2UtilBellatrix.ExecutionPayloadTransactions{Transactions: txs}
	txroot, err := transactions.HashTreeRoot()
	if err != nil {
		return nil, err
	}

	withdrawals := eth2UtilCapella.ExecutionPayloadWithdrawals{Withdrawals: p.Withdrawals}
	wdr, err := withdrawals.HashTreeRoot()
	if err != nil {
		return nil, err
	}

	return &deneb.ExecutionPayloadHeader{
		ParentHash:       p.ParentHash,
		FeeRecipient:     p.FeeRecipient,
		StateRoot:        p.StateRoot,
		ReceiptsRoot:     p.ReceiptsRoot,
		LogsBloom:        p.LogsBloom,
		PrevRandao:       p.PrevRandao,
		BlockNumber:      p.BlockNumber,
		GasLimit:         p.GasLimit,
		GasUsed:          p.GasUsed,
		Timestamp:        p.Timestamp,
		ExtraData:        p.ExtraData,
		BaseFeePerGas:    p.BaseFeePerGas,
		BlockHash:        p.BlockHash,
		TransactionsRoot: txroot,
		WithdrawalsRoot:  wdr,
		BlobGasUsed:      p.BlobGasUsed,
		ExcessBlobGas:    p.ExcessBlobGas,
	}, nil
}
