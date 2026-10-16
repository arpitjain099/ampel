// SPDX-FileCopyrightText: Copyright 2026 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"strings"
	"testing"

	signerOpts "github.com/policylabs/signer/options"

	"github.com/policylabs/ampel/pkg/verifier"
)

// TestVerifyOptions_SignGate locks in the rule that --sign is valid
// only when there is somewhere to write the produced attestation:
// either --attest-results (file output) or --format=attestation|
// vsa|svr (stdout output). Catches regressions of the gap where
// --sign was wired only to --attest-results.
func TestVerifyOptions_SignGate(t *testing.T) {
	const wantSignSubstr = "--sign requires --attest-results"

	base := func() verifyOptions {
		o := verifyOptions{
			VerificationOptions: verifier.NewVerificationOptions(),
			SignerSet:           signerOpts.DefaultSignerSet(),
			SubjectHash:         "sha256:abc123",
			PolicyLocation:      "/tmp/policy.json",
			Format:              "tty",
		}
		// Satisfy the unrelated "no attestation sources" check so
		// Validate doesn't short-circuit before the --sign gate.
		o.AttestationFiles = []string{"x"}
		return o
	}

	cases := []struct {
		name          string
		sign          bool
		attestResults bool
		format        string
		wantSignError bool
	}{
		{"no sign no gate", false, false, "tty", false},
		{"sign without target", true, false, "tty", true},
		{"sign with attest-results", true, true, "tty", false},
		{"sign with format=attestation", true, false, "attestation", false},
		{"sign with format=vsa", true, false, "vsa", false},
		{"sign with format=svr", true, false, "svr", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := base()
			o.Sign = tc.sign
			o.AttestResults = tc.attestResults
			o.Format = tc.format
			err := o.Validate()
			// Validate may surface unrelated errors (e.g. nonexistent
			// policy path); we only care about the --sign gate
			// message here.
			haveSignError := err != nil && strings.Contains(err.Error(), wantSignSubstr)
			if haveSignError != tc.wantSignError {
				t.Errorf("haveSignError=%v want=%v; full err=%v", haveSignError, tc.wantSignError, err)
			}
		})
	}
}

// --allow-skip may answer SKIP at the root, which a VSA or SVR cannot say,
// so the command asks the drivers and refuses the combination before
// evaluating anything.
func TestValidateAllowSkipRefusesVSA(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name          string
		allow, attest bool
		format        string
		attestFormat  string
		wantRefusal   bool
	}{
		{"vsa-without-allow-skip", false, false, "vsa", "ampel", false},
		{"allow-skip-with-tty", true, false, "tty", "ampel", false},
		{"allow-skip-with-attestation", true, true, "attestation", "ampel", false},
		{"allow-skip-with-vsa", true, false, "vsa", "ampel", true},
		{"allow-skip-with-svr", true, false, "svr", "ampel", true},
		{"allow-skip-attesting-vsa", true, true, "tty", "vsa", true},
		{"allow-skip-attesting-svr", true, true, "tty", "svr", true},
		{"allow-skip-attest-format-unused", true, false, "tty", "vsa", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			o := &verifyOptions{FailSkip: true}
			o.AllowSkip = tc.allow
			o.AttestResults = tc.attest
			o.Format = tc.format
			o.AttestFormat = tc.attestFormat
			err := o.Validate()
			// Other options are unset, so there are always errors; only the
			// refusal matters here.
			got := err != nil && (strings.Contains(err.Error(), "cannot render a SKIP result") || strings.Contains(err.Error(), "cannot record a SKIP result"))
			if got != tc.wantRefusal {
				t.Errorf("refused=%v want=%v; err=%v", got, tc.wantRefusal, err)
			}
		})
	}
}
