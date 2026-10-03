# Tool-profile benchmark

`bench/run.py` drives Claude Code headless against ida-mcp's tool profiles on
fixed reverse engineering tasks and records what each profile costs and
whether the agent got the right answer. It exists to settle one question with
receipts: does the smaller advertised tool set (`--profile lean`) change real
task cost or success compared with the full set?

Every trial is a fresh conversation (`claude -p`) in a fresh directory with a
fresh copy of the target binary. Only the profile under test is registered
(`--strict-mcp-config`); Claude Code's built-in tools (`--tools ""`) and
settings files (`--setting-sources ""`) are off, and inherited `IDA_MCP_*` and
MCP protocol opt-in variables are stripped, so the agent can reach neither the
repository nor another tool surface. Correctness is checked afterwards by the
harness, through ida-mcp, on the database the agent left behind; the oracles
never ask the model and never finish the task for it.

## Running

The trials call the Claude API and cost money. Run them from a normal
terminal, not an agent sandbox (Claude Code's credentials are not reachable
from one):

```fish
just bench --model claude-sonnet-5-5 --trials 3
```

Start with one trial per cell, read the receipts, then expand to three.

Options worth knowing (`python3 bench/run.py --help` has all of them):

- `--servers full,lean` and `--tasks annotate,xrefs,universal` choose the
  cells.
- `--protocol 2026-07-28` sets the Claude Code opt-in env vars for the new MCP
  lifecycle; the default `2025-11-25` is what the client speaks on its own.
  Compare profiles on the default first, then the protocol separately.
- `--effort <level>` passes Claude Code's effort setting; pin it along with the
  model when comparing runs.
- `--dsc <dyld_shared_cache>` enables the `dsc` task. The cache's directory
  must be writable (IDA creates a lock file beside it).
- `--out <dir>` must be a new directory; the default is a fresh one under the
  system temp dir, outside the repository so no project instructions apply.
  Copy a run you want to keep into `docs/.ai/bench/`.

To validate the harness without a model:

```fish
just bench-simulate
```

This performs each task correctly through ida-mcp, answering from the trial's
own database rather than from the pinned truth, and checks that every oracle
agrees, then runs negative controls (an invented function name, a
partial answer, a rename of the wrong function, a missing database, the
arm64 slice instead of x86_64, a vague count, a saved-but-unanalyzed stale
count, an extracted slice with no database, a different x86_64 binary with
the same function count) and checks that every oracle rejects them. Every
control asserts that its own setup succeeded before judging the oracle. It
exits non-zero if any requested cell fails or any control is accepted.

## Tasks

The target is `bench/target.c`, compiled by the harness as a thin arm64 Mach-O
and a universal arm64+x86_64 Mach-O, both with DWARF.

| task | the agent must | oracle |
|---|---|---|
| `annotate` | rename `helper_mix` to a descriptive name, comment it, save, close | at `helper_mix`'s original address: the name changed, equals the answer, and an address or function comment exists |
| `xrefs` | name every function referencing `"license expired"` | the answer's names equal the set IDA reports on the fixture (pinned per run in `fixtures/fixtures.json`) |
| `universal` | open the x86_64 slice and report the function count | the answer equals the count pinned from the fixture's x86_64 slice, and the agent left a saved 64-bit x86 database of that fixture (its recorded input hash is the frozen binary's or its extracted slice's) showing that count |
| `dsc` (opt-in) | open `libSystem.B.dylib` from a cache, add `libdyld.dylib`, report `dlopen` | the agent's database has libdyld loaded and the answer is exactly `_dlopen`'s address |

Ground truth is read from IDA on a private copy at the start of each run, not
from the C source: with `-O1` the compiler also materializes the string in
`main`, so four functions reference it, not the three the source suggests.
DSC trials point the server's temp dir at the trial so each gets its own
database instead of IDA's content-keyed reuse.

## Receipts

Per trial, `trials/<task>-<server>-<n>/` holds the prompt, the client's
`stream.jsonl` (kept even when the trial times out), the parsed `trial.json`
(usage by category, cost, turns, tool calls, tool errors, timeout flag, the
protocol version the server logged, the file inventory and any unpacked
databases as the agent left them, the oracle verdict, and `timings` split
into setup, agent, teardown, total, and oracle seconds), and the server log,
which names the shutdown signal the client sent. A trial whose setup, agent
run, or oracle raises (including a subprocess timeout or the oracle's own
server failing to start) is recorded as failed with the reason, its
pre-opened worker is always finished, and `trial.json` is always written.
The summary's `agent s` is the client's wall time; `total s` is the trial's
wall time excluding the harness's correctness check (`oracle_seconds`). Server order
alternates between trials. `summary.md` and `summary.json` are rewritten after every trial;
`pins.json` records the model, effort, requested protocol, Claude Code
version, ida-mcp commit and dirty flag, the binary's SHA-256, and each
profile's launch command.

Read the summary with these limits in mind:

- Three trials per cell shows gross differences, not small ones.
- Token counts are the client's own accounting, including cache categories;
  compare cells within one run, not across model or client versions.
- A failed oracle with many tool errors usually means the task prompt or the
  tool surface misled the agent; read the stream before blaming either.
