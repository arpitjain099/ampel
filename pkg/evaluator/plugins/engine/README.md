# Engine plugin

Exposes the verifier engine's own data to policies through the `ampel`
object, so a policy can react to the engine it runs on. Its main use is a
condition that makes a policy apply only to engines new enough to evaluate
it:

```json
"when": { "expression": "ampel.atLeast('v1.4.0')" }
```

| Method | Returns | Meaning |
| --- | --- | --- |
| `ampel.version()` | string | The engine's version as the build stamped it, `v1.4.1`. |
| `ampel.development()` | bool | Whether the engine was built from source, without a release version. |
| `ampel.newerThan(v)` | bool | The engine is newer than version `v`. |
| `ampel.olderThan(v)` | bool | The engine is older than version `v`. |
| `ampel.atLeast(v)` | bool | The engine is version `v` or newer. |
| `ampel.satisfies(c)` | bool | The engine's version satisfies constraint `c`, as in `>= 1.4, < 2`. |
| `ampel.started()` | timestamp | When the verification run started. |
| `ampel.runtime()` | string | The runtime evaluating the policy, `cel@v0`. |
| `ampel.plugins()` | list of strings | The plugins the runtime loaded, `semver@v0`, ... |
| `ampel.hasPlugin(name)` | bool | Whether a plugin is loaded, named with or without its version. |

A development build has no release version. It is newer than any release,
older than none and satisfies every constraint, so a policy written for a
newer engine never skips on a developer's own build. A version or constraint
that cannot be parsed is an evaluation error, never a silent answer.

The plugin's identity is `ampel@v0`. A policy that reads the object on an
engine that does not have it fails to compile, so a policy that must also
run on older engines names the plugin in its runtime and lets the
unsupported-runtime handling decide.
