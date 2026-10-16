// SPDX-FileCopyrightText: Copyright 2026 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"testing"
	"time"

	"cel.dev/cel-go/cel"
	"github.com/stretchr/testify/require"
)

var started = time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)

func release() *Engine {
	return &Engine{Version: "v1.4.1", Started: started, Runtime: "cel@v0", Plugins: []string{"semver@v0", "hasher@v0"}}
}

// run compiles and evaluates expr against a CEL env with the plugin loaded
// for the engine, returning the Go value produced.
func run(t *testing.T, e *Engine, expr string) any {
	t.Helper()
	p := NewWithEngine(e)
	env, err := cel.NewEnv(p.Library())
	require.NoError(t, err)
	ast, iss := env.Compile(expr)
	require.NoError(t, iss.Err(), "compile %q", expr)
	program, err := env.Program(ast, cel.EvalOptions(cel.OptOptimize))
	require.NoError(t, err)
	result, _, err := program.Eval(p.VarValues(nil, nil, nil))
	require.NoError(t, err, "eval %q", expr)
	return result.Value()
}

func TestData(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		expr string
		want any
	}{
		{`ampel.version()`, "v1.4.1"},
		{`ampel.runtime()`, "cel@v0"},
		{`ampel.started() == timestamp("2026-10-16T12:00:00Z")`, true},
		{`ampel.started() > timestamp("2026-01-01T00:00:00Z")`, true},
		{`size(ampel.plugins())`, int64(2)},
		{`"semver@v0" in ampel.plugins()`, true},
		{`ampel.development()`, false},
	} {
		t.Run(tc.expr, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.want, run(t, release(), tc.expr))
		})
	}
}

func TestVersionComparisons(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		expr string
		want bool
	}{
		{`ampel.newerThan("v1.4.0")`, true},
		{`ampel.newerThan("1.4.0")`, true},
		{`ampel.newerThan("v1.4.1")`, false},
		{`ampel.newerThan("v1.5.0")`, false},
		{`ampel.olderThan("v1.5.0")`, true},
		{`ampel.olderThan("v1.4.1")`, false},
		{`ampel.atLeast("v1.4.1")`, true},
		{`ampel.atLeast("v1.4.0")`, true},
		{`ampel.atLeast("v1.4.2")`, false},
		{`ampel.satisfies(">= 1.4, < 2")`, true},
		{`ampel.satisfies("~1.3")`, false},
		{`ampel.satisfies("^1.0")`, true},
	} {
		t.Run(tc.expr, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.want, run(t, release(), tc.expr))
		})
	}
}

// A build from source has no release version: it is newer than anything,
// older than nothing, and satisfies every constraint, so a conformance
// policy written for a newer engine never skips on a developer's build.
func TestDevelopmentBuild(t *testing.T) {
	t.Parallel()
	for _, e := range []*Engine{{Version: "devel"}, {Version: ""}, {Version: "(devel)"}} {
		require.True(t, e.Development())
		for _, tc := range []struct {
			expr string
			want bool
		}{
			{`ampel.development()`, true},
			{`ampel.newerThan("v99.0.0")`, true},
			{`ampel.olderThan("v0.0.1")`, false},
			{`ampel.atLeast("v99.0.0")`, true},
			{`ampel.satisfies("< 0.1")`, true},
		} {
			require.Equal(t, tc.want, run(t, e, tc.expr), "%q on version %q", tc.expr, e.Version)
		}
	}
	require.False(t, release().Development())
}

func TestPlugins(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		expr string
		want bool
	}{
		{`ampel.hasPlugin("semver")`, true},
		{`ampel.hasPlugin("semver@v0")`, true},
		{`ampel.hasPlugin("semver@v1")`, false},
		{`ampel.hasPlugin("osv")`, false},
	} {
		t.Run(tc.expr, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.want, run(t, release(), tc.expr))
		})
	}
}

// A bad argument is an evaluation error, never a silent answer.
func TestBadArguments(t *testing.T) {
	t.Parallel()
	p := NewWithEngine(release())
	env, err := cel.NewEnv(p.Library())
	require.NoError(t, err)
	for _, expr := range []string{`ampel.newerThan("not a version")`, `ampel.satisfies(">>> nope")`} {
		ast, iss := env.Compile(expr)
		require.NoError(t, iss.Err())
		program, err := env.Program(ast)
		require.NoError(t, err)
		_, _, err = program.Eval(p.VarValues(nil, nil, nil))
		require.Error(t, err, expr)
	}
	// And a method that does not exist does not compile.
	_, iss := env.Compile(`ampel.flavor()`)
	require.Error(t, iss.Err())
}

func TestFromBuild(t *testing.T) {
	t.Parallel()
	e := FromBuild()
	require.NotEmpty(t, e.Version)
	require.WithinDuration(t, time.Now(), e.Started, time.Minute)
	// The plugin of the running binary answers for it.
	require.Equal(t, e.Version, run(t, e, `ampel.version()`))
}
