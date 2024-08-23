// Copyright 2020 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package builder

import (
	"fmt"
	"time"

	"github.com/ethereum/go-ethereum/metrics"
)

var serveTimeHistName = "builder/duration"

// updateServeTimeHistogram tracks the serving time of serving a call.
func updateServeTimeHistogram(method string, success bool, elapsed time.Duration) {
	note := "success"
	if !success {
		note = "failure"
	}
	h := fmt.Sprintf("%s/%s/%s", serveTimeHistName, method, note)
	sampler := func() metrics.Sample {
		return metrics.NewExpDecaySample(1028, 0.015)
	}
	metrics.GetOrRegisterHistogramLazy(h, nil, sampler).Update(elapsed.Nanoseconds())
}
