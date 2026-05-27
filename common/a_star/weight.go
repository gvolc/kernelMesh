// Copyright Gleb Obitotsky <glebobitotsky@yandex.com> 2026.
//
// The code is distributed under the Mozilla Public License Version 2.0 license
// (you can find the license file in the root folder).

package astar

import (
	"math"
	"sync/atomic"
)

const maxLoss = 1.0

// const maxPathCost = 1e9

type GMetrics struct {
	loss   atomic.Uint64
	rtt    atomic.Uint64
	load   atomic.Uint64
	energy atomic.Uint64
}

type Weight struct {
	// Weight  atomic.Uint64
	metrics GMetrics
}

func storeFloat(dst *atomic.Uint64, val float64) {
	dst.Store(math.Float64bits(val))
}

func loadFloat(src *atomic.Uint64) float64 {
	return math.Float64frombits(src.Load())
}

func isValidTelemetry(val float64) bool {
	return !math.IsNaN(val) && !math.IsInf(val, 0)
}

func (gm *GMetrics) UpdateLoss(val float64) {
	if !isValidTelemetry(val) || val < 0 || val > maxLoss {
		return
	}
	storeFloat(&gm.loss, val)
	//bits := math.Float64bits(val)
	//gm.loss.Store(bits)
}

func (gm *GMetrics) UpdateRtt(val float64) {
	if !isValidTelemetry(val) || val < 0 {
		return
	}
	storeFloat(&gm.rtt, val)
	//bits := math.Float64bits(val)
	//gm.rtt.Store(bits)
}

func (gm *GMetrics) UpdateLoad(val float64) {
	if !isValidTelemetry(val) || val < 0 || val > 1.0 {
		return
	}
	storeFloat(&gm.load, val)
	//bits := math.Float64bits(val)
	//gm.load.Store(bits)
}

func (gm *GMetrics) UpdateEnergy(val float64) {
	if !isValidTelemetry(val) || val < 0 || val > 1.0 {
		return
	}
	storeFloat(&gm.energy, val)
	//bits := math.Float64bits(val)
	//gm.energy.Store(bits)
}

func (gm *GMetrics) GetLoss() float64 { return loadFloat(&gm.loss) }

func (gm *GMetrics) GetRtt() float64 { return loadFloat(&gm.rtt) }

func (gm *GMetrics) GetLoad() float64 { return loadFloat(&gm.load) }

func (gm *GMetrics) GetEnergy() float64 { return loadFloat(&gm.energy) }
