// Copyright Gleb Obitotsky <glebobitotsky@yandex.com> 2026.
//
// The code is distributed under the Mozilla Public License Version 2.0 license
// (you can find the license file in the root folder).

package astar

import (
	"math"
	"sync/atomic"
	//"golang.org/x/sys/cpu"
)

const maxLoss = 1.0

// const maxPathCost = 1e9

type TelemetrySnapshot struct {
	Loss   float64
	Rtt    float64
	Load   float64
	Energy float64
}

type GMetrics struct {
	//loss atomic.Uint64
	//_      cpu.CacheLinePad
	//rtt atomic.Uint64
	//_      cpu.CacheLinePad
	//load atomic.Uint64
	//_      cpu.CacheLinePad
	//energy atomic.Uint64

	data atomic.Pointer[TelemetrySnapshot]
}

//type Weight struct {
// Weight  atomic.Uint64
// metrics GMetrics
//}

func NewGMetrics() *GMetrics {
	gm := &GMetrics{}
	gm.data.Store(&TelemetrySnapshot{})
	return gm
}

//func storeFloat(dst *atomic.Uint64, val float64) {
//	dst.Store(math.Float64bits(val))
//}

//func loadFloat(src *atomic.Uint64) float64 {
//	return math.Float64frombits(src.Load())
//}

func isValidTelemetry(val float64) bool {
	return !math.IsNaN(val) && !math.IsInf(val, 0)
}

func (gm *GMetrics) UpdateLoss(val float64) {
	if !isValidTelemetry(val) || val < 0 || val > maxLoss {
		return
	}
	for {
		current := gm.data.Load()
		next := &TelemetrySnapshot{
			Loss:   val,
			Rtt:    current.Rtt,
			Load:   current.Load,
			Energy: current.Energy,
		}
		if gm.data.CompareAndSwap(current, next) {
			return
		}
	}
	//storeFloat(&gm.loss, val)
	//bits := math.Float64bits(val)
	//gm.loss.Store(bits)
}

func (gm *GMetrics) UpdateRtt(val float64) {
	if !isValidTelemetry(val) || val < 0 {
		return
	}
	for {
		current := gm.data.Load()
		next := &TelemetrySnapshot{
			Loss:   current.Loss,
			Rtt:    val,
			Load:   current.Load,
			Energy: current.Energy,
		}
		if gm.data.CompareAndSwap(current, next) {
			return
		}
	}
	//storeFloat(&gm.rtt, val)
	//bits := math.Float64bits(val)
	//gm.rtt.Store(bits)
}

func (gm *GMetrics) UpdateLoad(val float64) {
	if !isValidTelemetry(val) || val < 0 || val > 1.0 {
		return
	}
	for {
		current := gm.data.Load()
		next := &TelemetrySnapshot{
			Loss:   current.Loss,
			Rtt:    current.Rtt,
			Load:   val,
			Energy: current.Energy,
		}
		if gm.data.CompareAndSwap(current, next) {
			return
		}
	}
	//storeFloat(&gm.load, val)
	//bits := math.Float64bits(val)
	//gm.load.Store(bits)
}

func (gm *GMetrics) UpdateEnergy(val float64) {
	if !isValidTelemetry(val) || val < 0 || val > 1.0 {
		return
	}
	for {
		current := gm.data.Load()
		next := &TelemetrySnapshot{
			Loss:   current.Loss,
			Rtt:    current.Rtt,
			Load:   current.Load,
			Energy: val,
		}
		if gm.data.CompareAndSwap(current, next) {
			return
		}
	}
	//storeFloat(&gm.energy, val)
	//bits := math.Float64bits(val)
	//gm.energy.Store(bits)
}

//func (gm *GMetrics) GetLoss() float64 { return loadFloat(&gm.loss) }
//func (gm *GMetrics) GetRtt() float64 { return loadFloat(&gm.rtt) }
//func (gm *GMetrics) GetLoad() float64 { return loadFloat(&gm.load) }
//func (gm *GMetrics) GetEnergy() float64 { return loadFloat(&gm.energy) }

func (gm *GMetrics) GetSnapshot() TelemetrySnapshot { return *gm.data.Load() }
