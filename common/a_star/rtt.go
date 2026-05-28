// Copyright Gleb Obitotsky <glebobitotsky@yandex.com> 2026.
//
// The code is distributed under the Mozilla Public License Version 2.0 license
// (you can find the license file in the root folder).

package astar

import (
	"math"
	"sync/atomic"
)

// Formula RTT:
//
// const a = 0.125
// 500.0 - max ping
//
// RTT(smoothed) = (1 - a) * RTT(old) + a * RTT(new)
// final formula coefficient RTT: RTT(coefficient) = RTT(smoothed) / 500.0
//
// 0.0 <= RTT(coefficient) <= 1.0

const (
	coefficientA = 0.125
	maxPing      = 500.0
)

type Metrics struct {
	RttOld         float64
	RttNew         float64
	RttSmoothed    float64
	RttCoefficient float64
}

type Rtt struct {
	data atomic.Pointer[Metrics]
}

func NewRtt() *Rtt {
	rtt := &Rtt{}
	rtt.data.Store(&Metrics{})
	return rtt
}

func isValidRtt(val float64) bool {
	return !math.IsNaN(val) && !math.IsInf(val, 0) && val >= 0.0
}

func (rtt *Rtt) UpdateRttOld(val float64) {
	if !isValidRtt(val) {
		return
	}
	for {
		current := rtt.data.Load()
		new := &Metrics{
			RttOld:         val,
			RttNew:         current.RttNew,
			RttSmoothed:    current.RttSmoothed,
			RttCoefficient: current.RttCoefficient,
		}
		if rtt.data.CompareAndSwap(current, new) {
			return
		}
	}
}

func (rtt *Rtt) GetRtt() Metrics { return *rtt.data.Load() }
