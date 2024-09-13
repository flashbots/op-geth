package miner

import (
	"github.com/ethereum/go-ethereum/metrics"
)

var (
	blockProfitHistogram   = metrics.NewRegisteredHistogram("miner/block/profit", nil, metrics.NewExpDecaySample(1028, 0.015))
	blockProfitGauge       = metrics.NewRegisteredGauge("miner/block/profit/gauge", nil)
	culmulativeProfitGauge = metrics.NewRegisteredGauge("miner/block/profit/culmulative", nil)

	mergeAlgoTimer  = metrics.NewRegisteredTimer("miner/block/merge", nil)
	buildBlockTimer = metrics.NewRegisteredTimer("miner/block/build", nil)

	blockBundleSimulationTimer      = metrics.NewRegisteredTimer("miner/block/simulate", nil)
	successfulBundleSimulationTimer = metrics.NewRegisteredTimer("miner/bundle/simulate/success", nil)
	failedBundleSimulationTimer     = metrics.NewRegisteredTimer("miner/bundle/simulate/failed", nil)
	blockBundleNumHistogram         = metrics.NewRegisteredHistogram("miner/block/bundle/num", nil, metrics.NewExpDecaySample(1028, 0.015))

	simulationMeter          = metrics.NewRegisteredMeter("miner/block/simulation", nil)
	simulationCommittedMeter = metrics.NewRegisteredMeter("miner/block/simulation/committed", nil)
	simulationRevertedMeter  = metrics.NewRegisteredMeter("miner/block/simulation/reverted", nil)

	gasUsedGauge        = metrics.NewRegisteredGauge("miner/block/gasused", nil)
	transactionNumGauge = metrics.NewRegisteredGauge("miner/block/txnum", nil)
)
