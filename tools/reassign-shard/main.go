// Command reassign-shard moves one issuer, or every issuer currently on
// one shard, to a different shard (or shards) for all *future*
// allocations (docs/design.md §23). It never touches an issuer's
// already-issued credentials — those keep the shard_id recorded on
// their own list rows forever, from whenever they were actually
// allocated.
//
// This is a deliberate, infrequent, operator-driven action — a CLI
// against the AS's own Postgres directly, not a new admin API endpoint,
// matching this repo's convention for operational tools (tools/loadtest,
// tools/gen-fixture) rather than building new admin-auth machinery for
// something this rare.
//
// Usage:
//
//	# Move one issuer (rebalancing):
//	go run ./tools/reassign-shard -issuer some-issuer-id -to fra
//
//	# Empty a whole shard (region decommission — docs/design.md §23's
//	# worked example), splitting its issuers round-robin across two
//	# targets so the emptied shard's traffic doesn't just pile onto one
//	# new hotspot:
//	go run ./tools/reassign-shard -from iad -to fra,syd
//
//	# Always dry-run first:
//	go run ./tools/reassign-shard -from iad -to fra,syd -dry-run
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"strings"

	"github.com/sirosfoundation/siros-status-service/internal/as"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	dsn := flag.String("postgres-dsn", "postgres://postgres:postgres@localhost:5432/statuslist?sslmode=disable", "the AS's Postgres connection string (its issuer_shard table)")
	issuer := flag.String("issuer", "", "reassign this one issuer (mutually exclusive with -from)")
	from := flag.String("from", "", "reassign every issuer currently on this shard (mutually exclusive with -issuer)")
	to := flag.String("to", "", "destination shard, or a comma-separated list to split -from's issuers across round-robin")
	dryRun := flag.Bool("dry-run", false, "print what would change without writing anything")
	flag.Parse()

	if (*issuer == "") == (*from == "") {
		return fmt.Errorf("exactly one of -issuer or -from is required")
	}
	targets := strings.Split(*to, ",")
	for i := range targets {
		targets[i] = strings.TrimSpace(targets[i])
		if targets[i] == "" {
			return fmt.Errorf("-to must not contain an empty shard name")
		}
	}
	if len(targets) == 0 || targets[0] == "" {
		return fmt.Errorf("-to is required")
	}

	ctx := context.Background()
	// The shard list NewShardAssigner takes is only ever consulted by
	// AssignOrLookup's new-issuer path (irrelevant here) — passing the
	// destination shard(s) satisfies its "at least one configured"
	// guard without implying anything about this tool's own behavior.
	assigner, err := as.NewShardAssigner(ctx, *dsn, targets)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer assigner.Close()

	var issuers []string
	if *issuer != "" {
		issuers = []string{*issuer}
	} else {
		issuers, err = assigner.ListIssuersOnShard(ctx, *from)
		if err != nil {
			return fmt.Errorf("list issuers on shard %s: %w", *from, err)
		}
		if len(issuers) == 0 {
			fmt.Printf("shard %s has no assigned issuers — nothing to do\n", *from)
			return nil
		}
	}

	fmt.Printf("%d issuer(s) to reassign, split across %d target shard(s): %s\n", len(issuers), len(targets), strings.Join(targets, ", "))
	if *dryRun {
		fmt.Println("(dry run — no changes will be written)")
	}

	moved := 0
	for i, id := range issuers {
		target := targets[i%len(targets)]
		if *dryRun {
			fmt.Printf("  would move %s -> %s\n", id, target)
			continue
		}
		oldShard, err := assigner.Reassign(ctx, id, target)
		if err != nil {
			return fmt.Errorf("reassign %s: %w", id, err)
		}
		fmt.Printf("  %s: %s -> %s\n", id, displayShard(oldShard), target)
		moved++
	}

	if !*dryRun {
		fmt.Printf("done — %d issuer(s) reassigned. Existing access tokens keep routing to the old shard until they expire (ACCESS_TOKEN_TTL); "+
			"already-allocated credentials are unaffected regardless (docs/design.md §23) — only *new* allocations follow the change.\n", moved)
	}
	return nil
}

func displayShard(s string) string {
	if s == "" {
		return "(none — first assignment)"
	}
	return s
}
