// Copyright Gleb Obitotsky <glebobitotsky@yandex.com> 2026.
//
// The code is distributed under the Mozilla Public License Version 2.0 license
// (you can find the license file in the root folder).

package astar

// Formula RTT:
//
// const a = 0.125
// 500.0 - max ping
//
// RTT(smoothed) = (1 - a) * RTT(old) + a * RTT(new)
// final formula coefficient RTT: RTT(coefficient) = RTT(smoothed) / 500.0
//
// 0.0 <= RTT(coefficient) <= 1.0
