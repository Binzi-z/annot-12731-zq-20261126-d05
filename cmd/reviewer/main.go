// Command reviewer is the Windows-native offline log review tool.
//
// Usage:
//
//	reviewer selftest
//	reviewer demo [--out DIR]
//	reviewer verify-cert --cert CERT.json [--trust TRUST.json]
//	reviewer large
//
// It uses only the Go standard library and runs fully offline on locally
// synthesized data.
package main

import (
	"flag"
	"fmt"
	"os"

	"reviewer12731/internal/demo"
	"reviewer12731/internal/verify"
)

func main() {
	if len(os.Args) < 2 {
		if err := demo.Run("artifacts/demo", os.Stdout); err != nil {
			fatal(err)
		}
		return
	}
	cmd := os.Args[1]
	args := os.Args[2:]
	var err error
	switch cmd {
	case "selftest":
		err = verify.RunAll(os.Stdout)
	case "demo":
		fs := flag.NewFlagSet("demo", flag.ContinueOnError)
		out := fs.String("out", "artifacts/demo", "directory for certificates/reports")
		if perr := fs.Parse(args); perr != nil {
			err = perr
			break
		}
		err = demo.Run(*out, os.Stdout)
	case "verify-cert":
		err = runVerifyCert(args)
	case "large":
		err = demo.Large(os.Stdout)
	case "help", "-h", "--help":
		usage()
	default:
		err = fmt.Errorf("unknown command %q", cmd)
	}
	if err != nil {
		fatal(err)
	}
}

func usage() {
	fmt.Print(`reviewer12731 — offline hash-chain recovery reviewer

commands:
  selftest                 run all in-binary correctness/locality checks
  demo [--out DIR]         synthesize three sealed copies and produce reports+certs
  verify-cert --cert F [--trust T]
                           verify a minimal boundary certificate without the DB
  large                    build the large three-gap fixture and measure scans
`)
}

func runVerifyCert(args []string) error {
	fs := flag.NewFlagSet("verify-cert", flag.ContinueOnError)
	certPath := fs.String("cert", "", "path to conflict certificate JSON")
	trustPath := fs.String("trust", "", "optional trust bundle JSON (authenticity)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *certPath == "" {
		return fmt.Errorf("--cert is required")
	}
	return demo.VerifyCertFiles(*certPath, *trustPath, os.Stdout)
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "error: %v\n", err)
	os.Exit(1)
}
