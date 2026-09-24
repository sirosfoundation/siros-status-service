package main

import (
	"fmt"
	"slices"
	"time"
)

// opSummary is one operation's aggregated stats across every worker,
// merged after the timed run completes (not during — see runWorker's
// doc comment on why each worker keeps its own local slices).
type opSummary struct {
	op        string
	ok        int
	errors    int
	latencies []time.Duration
}

func (s opSummary) percentile(p float64) time.Duration {
	if len(s.latencies) == 0 {
		return 0
	}
	sorted := append([]time.Duration(nil), s.latencies...)
	slices.Sort(sorted)
	idx := int(p * float64(len(sorted)-1))
	return sorted[idx]
}

func mergeResults(results []*workerResult) map[string]*opSummary {
	summaries := map[string]*opSummary{
		"allocate":   {op: "allocate"},
		"status":     {op: "status"},
		"accounting": {op: "accounting"},
	}
	for _, r := range results {
		for op, lat := range r.latency {
			s := summaries[op]
			s.ok += len(lat)
			s.latencies = append(s.latencies, lat...)
		}
		for op, n := range r.errors {
			summaries[op].errors += n
		}
	}
	return summaries
}

func printReport(results []*workerResult, wallClock time.Duration) {
	summaries := mergeResults(results)
	totalSkipped := 0
	for _, r := range results {
		totalSkipped += r.skipped
	}

	fmt.Printf("\n=== load test report (%d issuers, %s wall clock) ===\n", len(results), wallClock.Round(time.Millisecond))
	fmt.Printf("%-12s %8s %8s %10s %10s %10s %10s %10s\n", "op", "ok", "errors", "rps", "p50", "p90", "p99", "max")
	for _, op := range []string{"allocate", "status", "accounting"} {
		s := summaries[op]
		rps := float64(s.ok) / wallClock.Seconds()
		fmt.Printf("%-12s %8d %8d %10.1f %10s %10s %10s %10s\n",
			s.op, s.ok, s.errors, rps,
			s.percentile(0.50).Round(time.Millisecond),
			s.percentile(0.90).Round(time.Millisecond),
			s.percentile(0.99).Round(time.Millisecond),
			s.percentile(1.0).Round(time.Millisecond),
		)
	}
	if totalSkipped > 0 {
		fmt.Printf("(%d 'status' attempts skipped — issuer had nothing allocated yet)\n", totalSkipped)
	}
}
