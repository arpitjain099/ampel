// SPDX-FileCopyrightText: Copyright 2026 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package cel

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/policylabs/ampel/pkg/evaluator/options"
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
