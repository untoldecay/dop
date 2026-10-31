package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/fray/dop/internal/approvalcard"
	"github.com/fray/dop/internal/approvalwindow"
)

// runApprover — `dop admin __approver`: the helper process behind the
// DOP approval window. Reads an approvalwindow.Request as JSON on stdin,
// shows the window, prints the Result as JSON on stdout. `--demo` shows
// a sample lease card and never decides: for looking at the character.
func runApprover(args []string) int {
	fs := flag.NewFlagSet("admin __approver", flag.ExitOnError)
	demo := fs.Bool("demo", false, "show a sample card; Approve / Deny only animate")
	mood := fs.String("mood", "routine", "with --demo: routine | amber | red")
	_ = fs.Parse(args)
	var req approvalwindow.Request
	if *demo {
		kind := approvalcard.KindLease
		switch *mood {
		case "amber":
			kind = approvalcard.KindProtectedGrant
		case "red":
			kind = approvalcard.KindPrintKeys
		}
		req = approvalwindow.Request{Demo: true, Lease: kind == approvalcard.KindLease, TimeoutMs: 60000,
			Card: approvalcard.Card{Kind: kind, Subject: "CamShell", Who: "buzz-reader (signed by its agent key)", Where: "srv1797015",
				Touches: "notion-outgrey.read-write, ytapi.read", Expires: time.Now().Add(14 * time.Minute),
				Options: approvalcard.LeaseOptions()}}
	} else if err := json.NewDecoder(os.Stdin).Decode(&req); err != nil {
		fmt.Fprintf(os.Stderr, "dop admin __approver: bad request: %v\n", err)
		return 2
	}
	res, err := approvalwindow.Run(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop admin __approver: %v\n", err)
		return 3 // unsupported: the caller falls back to the system alert
	}
	if *demo {
		return 0
	}
	return emitJSONTo(os.Stdout, res)
}

func emitJSONTo(w *os.File, v any) int {
	if err := json.NewEncoder(w).Encode(v); err != nil {
		return 1
	}
	return 0
}
