// SPDX-FileCopyrightText: Copyright 2026 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package cel

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/policylabs/ampel/pkg/evaluator/options"
	"github.com/policylabs/ampel/pkg/evaluator/plugins/engine"
)

// The ampel object is always in the environment and describes the
// evaluator that built it: its runtime and the plugins it loaded.
func TestEngineObject(t *testing.T) {
	t.Parallel()
	t.Run("with-default-plugins", func(t *testing.T) {
		t.Parallel()
		e, err := New()
		require.NoError(t, err)
		opts := options.Default
		for expr, want := range map[string]any{
			`ampel.runtime()`:                Class.String(),
			`ampel.hasPlugin("semver")`:      true,
			`ampel.hasPlugin("ampel@v0")`:    true,
			`"semver@v0" in ampel.plugins()`: true,
			`ampel.version() != ""`:          true,
			`ampel.newerThan("v0.0.1")`:      true, // any release, and a development build, is
		} {
			got, err := e.EvalExpression(context.Background(), &opts, expr)
			require.NoError(t, err, expr)
			require.Equal(t, want, got, expr)
		}
		require.Contains(t, e.RegisteredPlugins(), "ampel")
	})

	t.Run("without-default-plugins", func(t *testing.T) {
		t.Parallel()
		opts := options.Default
		opts.LoadDefaultPlugins = false
		e, err := NewWithOptions(&opts)
		require.NoError(t, err)
		got, err := e.EvalExpression(context.Background(), &opts, `ampel.hasPlugin("semver")`)
		require.NoError(t, err)
		require.Equal(t, false, got, "no plugin but the engine's own")
		got, err = e.EvalExpression(context.Background(), &opts, `ampel.plugins()`)
		require.NoError(t, err)
		require.Equal(t, []string{"ampel@v0"}, got)
	})
}

// The run's start, when the options carry it, is what ampel.started()
// answers, and stamping it never touches the plugin's own engine, which
// every evaluation shares.
func TestEngineRunStart(t *testing.T) {
	t.Parallel()
	e, err := New()
	require.NoError(t, err)
	started := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)

	opts := options.Default
	opts.RunStarted = started
	got, err := e.EvalExpression(context.Background(), &opts, `ampel.started() == timestamp("2026-10-16T12:00:00Z")`)
	require.NoError(t, err)
	require.Equal(t, true, got)

	// Without a run start the engine answers its own, which is now-ish.
	plain := options.Default
	got, err = e.EvalExpression(context.Background(), &plain, `ampel.started() > timestamp("2026-10-16T12:00:00Z")`)
	require.NoError(t, err)
	require.Equal(t, true, got)

	own := e.Plugins["ampel"].VarValues(nil, nil, nil)["ampel"].(*engine.Engine) //nolint:errcheck,forcetypeassert // the plugin binds its engine
	require.NotEqual(t, started, own.Started, "the plugin's engine is shared and must not be stamped")
}
