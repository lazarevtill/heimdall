package main

import (
	"sort"
	"time"

	"github.com/lazarevtill/heimdall/internal/bridge"
)

// The bridge's issue ledger: one row per (group, check) marker, tracking the
// tracker issue it opened, its per-target checklist, and whether it has been
// escalated or acked.
//
// WHICH DATABASE. The issue ledger lives in the BRIDGE's own db file
// (HEIMDALL_BRIDGE_DB) — the same file as the notify outbox, by deliberate
// design. It is NOT the engine state.db, which holds the finding ledger and
// suppressions. Opening the wrong one yields an empty page rather than an
// error, which is exactly the kind of quiet wrong answer this console exists
// to avoid, so the two handles are kept explicitly distinct in main.
//
// A NOTE ON "READ-ONLY". The console is NOT a read-only consumer of this
// file, in two ways, and both are worth stating rather than glossing:
//
//  1. bridge.OpenStore runs CREATE TABLE IF NOT EXISTS on open, so the
//     console may create empty tables on a database the bridge has not yet
//     initialised.
//  2. The outbox handle opened beside it (outbox.Open, cmd/heimdall-ui/main.go)
//     runs backfillLegacyDeliveries — an INSERT OR IGNORE into
//     notify_delivery — on EVERY open. That is a data-row write, not just
//     schema.
//
// Both are idempotent, both write only what the notifier would write anyway,
// and neither can alter or delete an existing row. But "the console only ever
// writes a mute" is false as an unqualified statement, so it is not made
// here. The accurate claim is: the console makes exactly one write to a
// DECISION authority (a suppression, via suppress.AddMute) and otherwise
// performs only idempotent schema/backfill migrations that its co-tenant
// daemons perform too.

// TicketView is one rendered issue row.
type TicketView struct {
	Marker      string
	Group       string
	Check       string
	Severity    string
	IssueID     string
	Escalated   bool
	Acked       bool
	OpenedAt    time.Time
	Opened      string
	Age         string
	FiringSince string
	// Tier reuses the signals page's reading scale so severities are drawn
	// the same way everywhere.
	Tier int

	// Targets is the per-target checklist: which targets of this group are
	// still firing.
	Targets []TicketTarget
	Firing  int
	Total   int
}

// TicketTarget is one checklist entry.
type TicketTarget struct {
	Target string
	Firing bool
}

// TicketsView is the whole page.
type TicketsView struct {
	Present bool
	Reason  string
	Tickets []TicketView
	// StormFuse is how many issues were opened in the last hour, the input
	// to the bridge's own rate limit.
	StormFuse    int
	StormWindow  string
	StormChecked bool
}

// stormWindow matches the bridge's own fuse window.
const stormWindow = time.Hour

// ReadTickets loads the open issue ledger.
//
// Fail-soft: a store error yields Present=false with a reason rather than a
// blank page, because "no open tickets" and "could not read the ledger" mean
// opposite things and must never look alike.
func ReadTickets(store *bridge.Store, now time.Time) TicketsView {
	if store == nil {
		return TicketsView{Reason: "No bridge database is configured, so the ticket ledger is unavailable."}
	}
	rows, err := store.ListOpen()
	if err != nil {
		return TicketsView{Reason: "The ticket ledger could not be read."}
	}

	v := TicketsView{Present: true}
	for _, r := range rows {
		tier, _ := classify("firing", r.Severity)
		tv := TicketView{
			Marker:    r.Marker,
			Group:     r.Group,
			Check:     r.Check,
			Severity:  r.Severity,
			IssueID:   r.IssueID,
			Escalated: r.Escalated,
			Acked:     r.Acked,
			Tier:      tier,
		}
		if !r.FiringSince.IsZero() {
			tv.FiringSince = HumanAge(now, r.FiringSince)
		}
		if !r.OpenedAt.IsZero() {
			tv.OpenedAt = r.OpenedAt.UTC()
			tv.Opened = r.OpenedAt.UTC().Format("2006-01-02 15:04:05Z")
			tv.Age = HumanAge(now, r.OpenedAt)
		} else {
			tv.Age = "unknown"
		}

		if targets, err := store.GetTargets(r.Marker); err == nil {
			names := make([]string, 0, len(targets))
			for name := range targets {
				names = append(names, name)
			}
			sort.Strings(names)
			for _, name := range names {
				firing := targets[name]
				tv.Targets = append(tv.Targets, TicketTarget{Target: name, Firing: firing})
				if firing {
					tv.Firing++
				}
			}
			tv.Total = len(names)
		}
		v.Tickets = append(v.Tickets, tv)
	}

	// Oldest-first: a ticket that has been open longest is the one that has
	// gone unattended longest.
	sort.SliceStable(v.Tickets, func(i, j int) bool {
		if !v.Tickets[i].OpenedAt.Equal(v.Tickets[j].OpenedAt) {
			return v.Tickets[i].OpenedAt.Before(v.Tickets[j].OpenedAt)
		}
		return v.Tickets[i].Marker < v.Tickets[j].Marker
	})

	if n, err := store.OpensSince(now.Add(-stormWindow)); err == nil {
		v.StormFuse = n
		v.StormChecked = true
		v.StormWindow = HumanDuration(stormWindow)
	}
	return v
}
