// Command fakephone stands in for the not-yet-built Android app: it scans
// (i.e. is given) a pairing URI, pairs with a real otpd over the LAN exactly
// as PROTOCOL.md specifies, and sends test SMS messages — including
// deliberately invalid ones, to exercise the daemon's rejection paths.
//
// Usage:
//
//	fakephone pair [-name NAME] [-state PATH] <otpfwd://...>
//	fakephone send [-sender S] [-body B] [-sim N] [-id ID] [-ctr N] [-ts-offset SECONDS] [-tamper] [-state PATH]
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "pair":
		runPair(os.Args[2:])
	case "send":
		runSend(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage:")
	fmt.Fprintln(os.Stderr, "  fakephone pair [-name NAME] [-state PATH] <otpfwd://...>")
	fmt.Fprintln(os.Stderr, "  fakephone send [-sender S] [-body B] [-sim N] [-id ID] [-ctr N] [-ts-offset SECONDS] [-tamper] [-state PATH]")
}

func runPair(args []string) {
	fs := flag.NewFlagSet("pair", flag.ExitOnError)
	name := fs.String("name", "fakephone", "device name to send during pairing")
	statePath := fs.String("state", defaultStatePath, "path to the state file to write")
	fs.Parse(args)

	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "usage: fakephone pair [-name NAME] [-state PATH] <otpfwd://...>")
		os.Exit(2)
	}

	if err := doPair(fs.Arg(0), *name, *statePath); err != nil {
		log.Fatalf("pair: %v", err)
	}
	fmt.Printf("paired successfully; state saved to %s\n", *statePath)
}

func runSend(args []string) {
	fs := flag.NewFlagSet("send", flag.ExitOnError)
	sender := fs.String("sender", "12345", "sender to report in the message")
	body := fs.String("body", "Your OTP is 123456. Do not share it.", "message body")
	sim := fs.Int("sim", 0, "sim slot to report (0 = omit)")
	id := fs.String("id", "", "override the message id — reuse a previous one to test replay rejection")
	ctr := fs.Int64("ctr", -1, "override the counter — reuse/lower a previous value to test counter rejection (-1 = use and advance the persisted counter)")
	tsOffset := fs.Int("ts-offset", 0, "seconds to offset the timestamp by; e.g. -200 to test stale-timestamp rejection")
	tamper := fs.Bool("tamper", false, "flip a ciphertext byte after sealing, to test tamper rejection")
	statePath := fs.String("state", defaultStatePath, "path to the state file written by `pair`")
	fs.Parse(args)

	opts := sendOpts{
		sender:   *sender,
		body:     *body,
		sim:      *sim,
		tsOffset: *tsOffset,
		tamper:   *tamper,
	}
	if *id != "" {
		opts.idOverride = *id
	}
	if *ctr >= 0 {
		v := uint64(*ctr)
		opts.ctrOverride = &v
	}

	if err := doSend(opts, *statePath); err != nil {
		log.Fatalf("send: %v", err)
	}
}
