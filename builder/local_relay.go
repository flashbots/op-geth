package builder

import (
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"strconv"
	"sync"

	builderSpec "github.com/attestantio/go-builder-client/spec"
	consensusspec "github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/phase0"
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

	bestSubmissionLock sync.Mutex
	bestSubmission     *builderSpec.VersionedSubmitBlockRequest

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

	r.bestSubmissionLock.Lock()
	r.bestSubmission = msg
	r.bestSubmissionLock.Unlock()

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

	r.bestSubmissionLock.Lock()
	bestSubmission := r.bestSubmission
	r.bestSubmissionLock.Unlock()

	log.Info("Received unblinded(trusted) block request", "bestSubmission", bestSubmission)

	if bestSubmission == nil {
		log.Error("no builder submissions")
		respondError(w, http.StatusInternalServerError, "no payloads")
		return
	}

	submittedSlot, err := bestSubmission.Slot()
	if err != nil {
		log.Error("could not get slot from best submission", "err", err)
		respondError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	if submittedSlot != uint64(slot) {
		log.Error("slot not equal", "requested", slot, "best", submittedSlot)
		respondError(w, http.StatusBadRequest, fmt.Sprintf("slot not equal requested: %d bestPayload: %d", slot, submittedSlot))
		return
	}

	submittedParentHash, err := bestSubmission.ParentHash()
	if err != nil {
		log.Error("could not get parent hash from best submission", "err", err)
		respondError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	if submittedParentHash.String() != parentHashHex {
		log.Error("parent hash not equal", "requested", parentHashHex, "best", submittedParentHash.String())
		respondError(w, http.StatusBadRequest, fmt.Sprintf("parent hash not equal requested: %s bestPayload: %s", parentHashHex, submittedParentHash.String()))
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
