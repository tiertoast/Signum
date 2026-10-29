"""Reject diagnostics introduced by the S04 owner and termination scheduler."""
import argparse, pathlib, re

def warnings(text):
    return [line for line in text.splitlines() if re.search(r"\.swift:\d+:\d+: warning:", line) and
            ("SigningWindowSession.swift:" in line or ("/SignumApp/main.swift:" in line and "non-Sendable" in line))]

if __name__ == "__main__":
    p = argparse.ArgumentParser(); p.add_argument("--self-test", action="store_true"); p.add_argument("logs", nargs="*"); args = p.parse_args()
    fixture = "/s/SigningWindowSession.swift:8:46: warning: conformance crosses into main actor\n/s/SignumApp/main.swift:30:132: warning: non-Sendable parameter\n/s/Other.swift:1:2: warning: unrelated"
    assert len(warnings(fixture)) == 2 and not warnings("Build complete!")
    print("S04_STRICT_CONTROL PASS: both S04 roots, unrelated diagnostic, clean log")
    rejected = False
    for name in args.logs:
        text = pathlib.Path(name).read_text(); assert "Build complete!" in text, "Incomplete build: " + name
        found = warnings(text); print(name, found); rejected |= bool(found)
    if not args.self_test and not args.logs: p.error("provide completed build logs")
    raise SystemExit(1 if rejected else 0)
