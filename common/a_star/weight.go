// Copyright Gleb Obitotsky <glebobitotsky@yandex.com> 2026.
//
// The code is distributed under the Mozilla Public License Version 2.0 license
// (you can find the license file in the root folder).

package astar

type Weight struct {
	G      float64
	P      float64
	RTT    float64
	Load   float64
	Energy float64
}
