# Fixed 14-C.2 memory experiment

Diagnostic tooling only. Not a SwiftPM product, worker, application cache, or test
assertion about machine speed. Uses the official `scripts/test-local.py` Run
watchdog. Requires the same prepared native prefix/toolchain as LOCAL_TESTING,
WindowServer, and only synthetic inputs. No downloads or global installation.

Use two clean Git archive source directories and new output roots. Prepare each
with `build.py --source SOURCE --revision COMMIT --prefix PREFIX --cmake CMAKE
--output-root NEW_PARENT`. This builds Release Core/worker (`-enable-testing` only
for internal phase access), Release helper plus its ordinary CTest, and an
isolated synthetic software provider. `profile-build.json` records the paths;
`source-sha256.json` records the actual source bytes. A representative invocation:

```
python3 Tools/MemoryProfile/run.py --source SOURCE --build BUILD_ROOT \
  --helper HELPER --fixture SHARED_SYNTHETIC_PROVIDER_DIRECTORY \
  --fixtures SHARED_SYNTHETIC_DOCUMENT_DIRECTORY --label baseline \
  --output-root NEW_PARENT --sizes 1,16,50,100 --repetitions 3
```

Run exactly the same script and **same provider, certificate, key and document
fixtures** against both builds, sequentially. The first run generates inert PDF
padding fixtures of exact sizes without overwriting existing files. Input hashes
are in fixtures.json. The CMS builder has no wall-clock signing attribute: its
outputs should also compare byte-for-byte across builds. OpenSSL checks the
extracted document hash. PAdES timestamps/field IDs are intentionally variable;
verify integrity, source prefix and geometry instead of comparing file hashes.

Each phase command starts a fresh process. The probe calls production Core and
App helper/preview code. It measures capture/clone/read/hash, CMS preparation and
composition, bounded metadata, attached verification, bound v2/v5 jobs, unsigned
and signed verification, extraction/PNG preview, and the actual production
placement pane hosted with synthetic data. It never runs application discovery.
Incremental signing is measured below 100 MiB; a first signed 100 MiB source
exceeds the existing 100 MiB input limit. Two-document batches use 1/16/50 MiB
inputs; 100+100 is outside the 128 MiB session limit. Use `--budget-only` for a
separate 32×4 MiB acquisition/review/reset experiment at that limit.

A standalone worker is separately measured with its own fresh, distinct synthetic
job ID and independently verified RSA response. The bounded synthetic stdin
request is deleted and never logged. OpenSSL is separately measured too. No
retries, authorization/session reuse, PIN caching, or provider parallelism.

`/usr/bin/time -l` records wait-resource data. A local parent/150 MiB child
control shows that its reported maximum RSS includes the child high-water value
on the observed Darwin host (parent SELF ~1.7 MiB, time ~151 MiB). Use
RUSAGE_SELF checkpoint peaks for parents, and time RSS/CPU/footprint only for
separately measured leaf worker/helper/verifier processes. Never label time RSS
from a parent with subprocesses as that parent’s memory or a pipeline total.
Checkpoints record current Mach resident bytes, SELF peak RSS, CPU/wall time and Darwin
process-attributed disk bytes. These disk counters depend on cache state and are
not logical read/write totals. CaptureIO counts clone calls and actual capture
read bytes/calls. Logical read/hash/copy counts from source inspection must be
identified separately. `childrenPeakRSS` is cumulative child rusage, **not** an
individual worker measurement or simultaneous pipeline total; use the standalone
worker/helper/verifier results. A view host is not the complete GUI process.

`native-phases.py` supplements the unmodified-helper comparisons by adding fixed
markers in a new isolated source copy. Pass --source/--prefix/--cmake/--fixture/
--fixtures/--output-root. It records source/vector capacities, PoDoFo parsing,
incremental signing/appearance, writer conversion, staged readback and final
verification, in three fresh processes per size. It also measures a separate
native unified verification process and checks every signature. Markers use an
inherited pipe: the verifier's RLIMIT_FSIZE=0 and all ordinary limits remain active.
Only the external adapter writes diagnostics. Instrumented CPU/I/O includes small
marker overhead and must remain separate from unmodified helper measurements.
No pointer/ownership/sanitizer/lifecycle changes are introduced by instrumentation.

Fixtures isolate byte amplification with mostly constant parse complexity. They
do not bound arbitrary compressed/raster PDFs, SDK caches, allocator retention,
all interleavings, or minimum-macOS GUI latency. Post-scope RSS is not proof of a
leak or secure erasure. Retained approval values intentionally keep immutable
snapshot bytes alive after files retire. ASAN uses detect_leaks=0; its post-unload
reporting limitation remains as documented in the gate report.

For an unmodified helper's per-process resource comparison, pass
`native-phases.py --unmodified-helper HELPER` with the same other arguments.
It skips instrumentation/build, records the executable hash, and executes the
same synthetic sign/verify cases. Marker arrays are intentionally empty; use
usage.txt and verify-usage.txt. Compare this before/after separately from phase
observations, then run the complete official suite on the final clean sources.
