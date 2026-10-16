// SPDX-FileCopyrightText: Copyright 2026 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

// Package attest writes attestations capturing evaluation results in
// the format chosen by the caller. It is the home for the signing
// pipeline that will turn ampel results into signed attestations —
// for now it covers the format dispatch and intoto statement
// construction so call sites that move to it today don't change shape
// when signing lands.
package attest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"slices"
	"strings"

	"github.com/policylabs/attestation"
	"github.com/policylabs/collector/statement/intoto"
	papi "github.com/policylabs/policy/api/v1"
	"github.com/policylabs/predicates"
	"github.com/policylabs/signer"
)

// ampelVerifierID is the verifier identifier embedded in every
// attestation produced by this package (VSA, SVR, and the ampel
// resultset format).
const ampelVerifierID = "https://carabiner.dev/ampel@v1"

// formatAmpel is the canonical name of the native ampel resultset
// attestation format.
const formatAmpel = "ampel"

// ResultsAttester writes a results attestation in the format chosen
// per call via WithFormat. The "ampel" format produces an in-toto
// statement carrying a predicates.ResultSet; "vsa" and "svr" route
// through their format-specific drivers.
//
// FnOpts passed to New populate the attester's defaults; the same
// FnOpts passed to AttestTo / AttestToFile override those defaults
// for one call. A typical CLI configures once via New (e.g. with a
// pre-built *signer.Signer) and never overrides; library callers
// can stay stateless and pass options per call instead.
type ResultsAttester struct {
	defaults Options
	formats  map[string]Format
}

// New returns a ResultsAttester with optional instance-level
// defaults. Pass FnOpts here when the same configuration applies to
// every call (typical CLI use); otherwise leave empty and pass
// options per call.
func New(opts ...FnOpt) *ResultsAttester {
	a := &ResultsAttester{defaults: defaultAttestOptions(), formats: defaultFormats()}
	for _, fn := range opts {
		fn(&a.defaults)
	}
	return a
}

// FnOpt configures a ResultsAttester. Passed to New, it sets
// instance-wide defaults; passed to AttestTo / AttestToFile, it
// overrides those defaults for that one call.
type FnOpt func(*Options)

// Options is the resolved configuration for one Attest* call. A Format
// receives it and honors PrettyPrint and Signer, through WriteStatement.
type Options struct {
	// Format is the name of the format to write.
	Format string
	// PrettyPrint indents the JSON of an unsigned statement.
	PrettyPrint bool
	// Signer signs the statement when set.
	Signer *signer.Signer
}

// Format writes results attestations in one format. Beyond writing, a
// format says which evaluation statuses it can record: a VSA or SVR, for
// example, has no way to say SKIP. A caller that may answer a status asks
// before evaluating, so a run never ends in an attestation that cannot be
// written. Custom formats are added with RegisterFormat.
type Format interface {
	// Attest writes the attestation for results to w, honoring opts.
	Attest(w io.Writer, results papi.Results, opts *Options) error
	// SupportsStatus reports whether a result with the status can be
	// recorded in the format.
	SupportsStatus(status string) bool
}

// ampelFormat is the native results attestation: it records every status.
type ampelFormat struct{}

func (ampelFormat) Attest(w io.Writer, results papi.Results, opts *Options) error {
	return attestAmpel(w, results, *opts)
}

func (ampelFormat) SupportsStatus(status string) bool { return status != "" }

// verdictFormat is shared by the formats that only know a verdict, PASSED
// or FAILED: a VSA and an SVR. They record a soft failure as passed and
// cannot record a skip.
type verdictFormat struct {
	attest func(w io.Writer, results papi.Results, opts Options) error
}

func (f verdictFormat) Attest(w io.Writer, results papi.Results, opts *Options) error {
	return f.attest(w, results, *opts)
}

func (verdictFormat) SupportsStatus(status string) bool {
	switch status {
	case papi.StatusPASS, papi.StatusFAIL, papi.StatusSOFTFAIL:
		return true
	default:
		return false
	}
}

// defaultFormats are the formats every attester starts with.
func defaultFormats() map[string]Format {
	return map[string]Format{
		formatAmpel: ampelFormat{},
		"vsa":       verdictFormat{attest: attestVSA},
		"svr":       verdictFormat{attest: attestSVR},
	}
}

// RegisterFormat adds a format under name, replacing one of that name.
func (a *ResultsAttester) RegisterFormat(name string, f Format) {
	a.formats[name] = f
}

// Formats lists the names of the formats the attester can write.
func (a *ResultsAttester) Formats() []string {
	return slices.Sorted(maps.Keys(a.formats))
}

// SupportsStatus reports whether the named format can record a result
// with the status. An unknown format supports nothing. An empty format
// name is the ampel format, as in WithFormat.
func (a *ResultsAttester) SupportsStatus(format, status string) bool {
	f, ok := a.formats[formatName(format)]
	return ok && f.SupportsStatus(status)
}

// formatName resolves the empty format name to the ampel format.
func formatName(format string) string {
	if format == "" {
		return formatAmpel
	}
	return format
}

// defaultAttestOptions returns the baseline config used when no
// FnOpts are supplied at construction or call time.
func defaultAttestOptions() Options {
	return Options{Format: formatAmpel, PrettyPrint: true}
}

// WithFormat selects the results-attestation format for the call.
// Must be one of verifier.ResultsAttestationFormats. Empty resolves
// to "ampel" at dispatch, so passing through an unset
// AttestFormat option is safe.
func WithFormat(format string) FnOpt {
	return func(o *Options) {
		o.Format = format
	}
}

// WithPrettyPrint controls JSON formatting of the unsigned
// attestation. The default is true (2-space indented output); pass
// false for a single-line compact form.
//
// When a signer is configured via WithSigner this option is a
// no-op — the produced *signer.SignedArtifact serializes with the
// formatting dictated by its kind (sigstore Bundle: compact;
// DSSE envelope: indented).
func WithPrettyPrint(enabled bool) FnOpt {
	return func(o *Options) {
		o.PrettyPrint = enabled
	}
}

// WithSigner configures the attester to sign the produced
// attestation instead of writing the raw in-toto Statement. The
// output shape becomes the *signer.SignedArtifact's canonical JSON
// form (sigstore Bundle for the sigstore/SPIFFE backends, DSSE
// envelope for the key backend).
//
// nil resets to the unsigned path — useful per-call to override an
// instance-level default set at New time.
func WithSigner(s *signer.Signer) FnOpt {
	return func(o *Options) {
		o.Signer = s
	}
}

// AttestToFile writes the results attestation for results to path,
// truncating any existing file. The attestation is rendered in full
// before the file is touched, so a refused or failed attestation leaves
// no file behind. Per-call FnOpts override any defaults set at New time.
func (a *ResultsAttester) AttestToFile(path string, results papi.Results, opts ...FnOpt) error {
	var buf bytes.Buffer
	if err := a.AttestTo(&buf, results, opts...); err != nil {
		return err
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil { //nolint:gosec // an attestation is meant to be read
		return fmt.Errorf("writing results attestation: %w", err)
	}
	return nil
}

// AttestTo writes the results attestation for results to w. The
// effective configuration is the attester's defaults overlaid with
// any per-call FnOpts. Splitting the writer- and path-based entry
// points keeps the dispatch testable without touching the filesystem.
func (a *ResultsAttester) AttestTo(w io.Writer, results papi.Results, opts ...FnOpt) error {
	o := a.defaults
	for _, fn := range opts {
		fn(&o)
	}
	f, ok := a.formats[formatName(o.Format)]
	if !ok {
		return fmt.Errorf("unknown attestation format %q", o.Format)
	}
	return f.Attest(w, results, &o)
}

// WriteStatement writes stmt to w in either its raw in-toto JSON
// form (when no signer is configured) or as a signer.SignedArtifact
// (sigstore Bundle or DSSE envelope, depending on the backend).
// All format-specific writers, custom formats included, funnel through
// it so the signing dispatch lives in exactly one place.
func WriteStatement(w io.Writer, stmt *intoto.Statement, o Options) error {
	if o.Signer == nil {
		return writeStatementJSON(w, stmt, o.PrettyPrint)
	}
	data, err := json.Marshal(stmt)
	if err != nil {
		return fmt.Errorf("serializing statement for signing: %w", err)
	}
	artifact, err := o.Signer.SignStatement(data)
	if err != nil {
		return fmt.Errorf("signing statement: %w", err)
	}
	if _, err := artifact.WriteTo(w); err != nil {
		return fmt.Errorf("writing signed artifact: %w", err)
	}
	return nil
}

// attestAmpel writes an "ampel"-format results attestation. Result
// and ResultGroup inputs are wrapped into a single-entry ResultSet
// before serialization so every output is the same shape.
func attestAmpel(w io.Writer, results papi.Results, o Options) error {
	switch r := results.(type) {
	case *papi.Result:
		rs := &papi.ResultSet{
			Subject:   r.Subject,
			Results:   []*papi.Result{r},
			DateStart: r.DateStart,
			DateEnd:   r.DateEnd,
		}
		if err := rs.Assert(); err != nil {
			return fmt.Errorf("asserting results set: %w", err)
		}
		return writeResultSet(w, rs, o)
	case *papi.ResultSet:
		return writeResultSet(w, r, o)
	case *papi.ResultGroup:
		rs := &papi.ResultSet{
			Subject:   r.Subject,
			Groups:    []*papi.ResultGroup{r},
			DateStart: r.DateStart,
			DateEnd:   r.DateEnd,
		}
		if err := rs.Assert(); err != nil {
			return fmt.Errorf("asserting results set: %w", err)
		}
		return writeResultSet(w, rs, o)
	default:
		return errors.New("results are not Result, ResultSet or ResultGroup")
	}
}

// writeStatementJSON serializes stmt to w in either 2-space indented
// or compact single-line JSON. Used by every format-specific writer
// so the WithPrettyPrint behavior stays consistent across ampel, VSA
// and SVR output.
func writeStatementJSON(w io.Writer, stmt *intoto.Statement, pretty bool) error {
	var (
		data []byte
		err  error
	)
	if pretty {
		data, err = json.MarshalIndent(stmt, "", "  ")
	} else {
		data, err = json.Marshal(stmt)
	}
	if err != nil {
		return fmt.Errorf("serializing statement: %w", err)
	}
	if _, err := w.Write(data); err != nil {
		return fmt.Errorf("writing statement: %w", err)
	}
	return nil
}

// writeResultSet builds an in-toto statement carrying a
// predicates.ResultSet and writes it via WriteStatement. The statement
// is about the subject the set was evaluated against, not about the
// subjects recorded in its results: chained evaluations look at other
// artifacts along the way, but the verdict is still about the original
// subject.
func writeResultSet(w io.Writer, resultset *papi.ResultSet, o Options) error {
	if resultset == nil {
		return errors.New("unable to attest results, set is nil")
	}
	if len(resultset.GetSubject().GetDigest()) == 0 {
		return errors.New("unable to attest results, the set has no subject with digests")
	}

	stmt := intoto.NewStatement()
	stmt.AddSubject(resultset.GetSubject())
	stmt.PredicateType = predicates.PredicateTypeResultSet
	stmt.Predicate = &predicates.ResultSet{Parsed: resultset}

	return WriteStatement(w, stmt, o)
}

// stringifyDigests returns a canonical algo:value/algo:value... form
// of subject's digest map suitable for set-membership checks.
func stringifyDigests(subject attestation.Subject) string {
	digest := subject.GetDigest()
	s := make([]string, 0, len(digest))
	for algo, val := range digest {
		s = append(s, fmt.Sprintf("%s:%s", algo, val))
	}
	slices.Sort(s)
	return strings.Join(s, "/")
}
