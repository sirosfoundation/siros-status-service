package main

import (
	"context"
	"fmt"
	"sort"

	"github.com/redis/go-redis/v9"

	"github.com/sirosfoundation/siros-status-service/internal/statuslist"
	"github.com/sirosfoundation/siros-status-service/internal/store"
)

// printPoolBalance summarizes how evenly this run's own allocations
// landed across lists — a rough, load-test-local echo of
// internal/pool/pool_test.go's real mixing-property checks (docs/
// design.md §8.1's power-of-two-choices placement should keep every
// list's share within reach of the mean, not dominated by one or two).
// This only reflects what THIS run allocated, not a list's full
// lifetime history, so it's a sanity signal, not a substitute for that
// unit test.
func printPoolBalance(results []*workerResult) {
	perList := map[string]int{}
	total := 0
	for _, r := range results {
		for _, a := range r.allocs {
			perList[a.listID]++
			total++
		}
	}
	if total == 0 || len(perList) == 0 {
		fmt.Println("\n=== pool balance: no allocations recorded, nothing to check ===")
		return
	}
	mean := float64(total) / float64(len(perList))

	type row struct {
		listID string
		count  int
	}
	rows := make([]row, 0, len(perList))
	for id, c := range perList {
		rows = append(rows, row{id, c})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].count > rows[j].count })

	fmt.Printf("\n=== pool balance: %d allocations across %d lists (mean %.0f/list) ===\n", total, len(rows), mean)
	for _, r := range rows {
		flag := ""
		if float64(r.count) > mean*1.5 {
			flag = "  <- more than 1.5x the mean; check §8.1 mixing if this recurs"
		}
		fmt.Printf("  %-40s %6d (%5.1f%%)%s\n", r.listID, r.count, 100*float64(r.count)/float64(total), flag)
	}
}

// verifyDecoySafety re-reads every index this run allocated or patched
// directly from the shard's own stores and compares it against what
// this harness itself last wrote (allocRecord.expected). A mismatch
// means something — most plausibly internal/decoy, given this is
// exactly the invariant docs/design.md §17 depends on — silently
// overwrote a real credential's real status. Any single mismatch is
// reported individually: this is a correctness check, not a sampled
// metric, so it never summarizes past the first N failures the way a
// latency report would.
func verifyDecoySafety(ctx context.Context, postgresDSN, redisAddr string, results []*workerResult) error {
	meta, err := store.NewMetaStore(ctx, postgresDSN)
	if err != nil {
		return fmt.Errorf("verify: connect postgres: %w", err)
	}
	defer meta.Close()

	rdb := redis.NewClient(&redis.Options{Addr: redisAddr})
	defer func() { _ = rdb.Close() }()
	bitmaps := store.NewBitmapStore(rdb)

	listMetaCache := map[string]*store.ListMeta{}
	snapshotCache := map[string][]byte{}
	mismatches := 0
	checked := 0

	for _, r := range results {
		for _, rec := range r.allocs {
			lm, ok := listMetaCache[rec.listID]
			if !ok {
				lm, err = meta.GetList(ctx, rec.listID)
				if err != nil || lm == nil {
					return fmt.Errorf("verify: could not load list %s: %w", rec.listID, err)
				}
				listMetaCache[rec.listID] = lm
			}

			raw, ok := snapshotCache[rec.listID]
			if !ok {
				byteLen := int64((lm.Size*uint64(lm.Bits) + 7) / 8)
				raw, err = bitmaps.Snapshot(ctx, rec.listID, byteLen)
				if err != nil {
					return fmt.Errorf("verify: snapshot list %s: %w", rec.listID, err)
				}
				snapshotCache[rec.listID] = raw
			}

			bm, err := statuslist.WrapBitmap(raw, lm.Size, lm.Bits)
			if err != nil {
				return fmt.Errorf("verify: wrap bitmap for %s: %w", rec.listID, err)
			}
			actual, err := bm.Get(rec.index)
			if err != nil {
				return fmt.Errorf("verify: read index %d in %s: %w", rec.index, rec.listID, err)
			}
			checked++
			if statusName(actual) != rec.expected {
				mismatches++
				fmt.Printf("  MISMATCH issuer=%s list=%s index=%d expected=%s actual=%s\n",
					r.issuerID, rec.listID, rec.index, rec.expected, statusName(actual))
			}
		}
	}

	fmt.Printf("\n=== decoy safety: checked %d indices, %d mismatches ===\n", checked, mismatches)
	if mismatches > 0 {
		return fmt.Errorf("verify: %d indices had a status this harness never wrote — see docs/design.md §17", mismatches)
	}
	return nil
}

func statusName(s statuslist.Status) string {
	switch s {
	case statuslist.StatusValid:
		return "VALID"
	case statuslist.StatusInvalid:
		return "INVALID"
	case statuslist.StatusSuspended:
		return "SUSPENDED"
	default:
		return fmt.Sprintf("UNKNOWN(%#x)", byte(s))
	}
}
