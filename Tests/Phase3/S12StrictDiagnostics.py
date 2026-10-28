"""Read completed compiler logs; never builds or changes a language setting."""
import argparse
import json
import pathlib
import re


def diagnostics(text):
    # Match diagnostic headers, excluding repeated source excerpts and notes.
    return [line for line in text.splitlines() if re.search(r"\.swift:\d+:\d+: warning:", line)]


def related(lines):
    return [line for line in lines if
            ("EuropeanCatalog.swift:" in line and "clock" in line) or
            ("SignumNativeWorkspace.swift:" in line and "deinit" in line)]


def controls():
    sample = "\n".join([
        "/source/EuropeanCatalog.swift:119:21: warning: sending 'clock' risks causing data races",
        "/source/SignumNativeWorkspace.swift:116:17: warning: cannot access property 'closeObserver' with a non-Sendable type '(any NSObjectProtocol)?' from nonisolated deinit",
        "/source/Other.swift:1:1: warning: unrelated diagnostic",
        " 116 | deinit { if let closeObserver { ... } }",
    ])
    assert len(diagnostics(sample)) == 3
    assert len(related(diagnostics(sample))) == 2
    assert diagnostics("Build complete!") == []
    print("S12_CLASSIFIER_CONTROL PASS: warning headers, both finding roots, unrelated warning and excerpts")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("logs", nargs="*")
    args = parser.parse_args()
    controls()
    if not args.self_test and not args.logs:
        parser.error("provide completed strict-concurrency build logs")
    rejected = False
    for name in args.logs:
        text = pathlib.Path(name).read_text()
        assert "Build complete!" in text, "Incomplete or invalid build fixture: " + name
        all_warnings = diagnostics(text)
        finding = related(all_warnings)
        print(json.dumps(dict(log=name, warnings=all_warnings, findingWarnings=finding)))
        rejected |= bool(finding)
    raise SystemExit(1 if rejected else 0)
