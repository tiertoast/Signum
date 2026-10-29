#!/usr/bin/env python3
"""Offline contract: compiled XCTest discovery, manifest coverage, real execution."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re


def qualified(name):
    if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)?', name):
        raise ValueError('Invalid XCTest class: ' + repr(name))
    return name if '.' in name else 'SignumCoreTests.' + name


def declared_classes(manifest):
    groups = manifest.get('groups')
    if not isinstance(groups, dict) or not groups:
        raise ValueError('Manifest requires nonempty groups')
    included = []
    for name, values in groups.items():
        if not isinstance(values, list): raise ValueError('Group must be an array: ' + name)
        included.extend(qualified(value) for value in values)
    excluded = manifest.get('excluded', {})
    if not isinstance(excluded, dict) or any(not isinstance(reason, str) or not reason.strip() for reason in excluded.values()):
        raise ValueError('Every excluded class needs a nonempty reason')
    excluded = {qualified(name): reason for name, reason in excluded.items()}
    all_names = included + list(excluded)
    duplicate = sorted(name for name, count in Counter(all_names).items() if count != 1)
    if duplicate: raise ValueError('Classes assigned more than once: ' + ', '.join(duplicate))
    for requirement, names in manifest.get('requires', {}).items():
        if any(qualified(name) not in included for name in names):
            raise ValueError('Unknown class in prerequisite ' + requirement)
    return set(included), excluded


def check_classes(actual, manifest):
    included, excluded = declared_classes(manifest)
    actual = set(actual)
    missing = sorted(actual - included - set(excluded))
    stale = sorted((included | set(excluded)) - actual)
    if missing or stale:
        raise ValueError('XCTest manifest mismatch; unclassified=' + repr(missing) + '; absent=' + repr(stale))
    return dict(included=sorted(included), excluded=excluded, classes=len(actual))


def source_classes(root):
    return {folder.name + '.' + name
            for folder in (Path(root) / 'Tests').iterdir() if folder.is_dir()
            for source in folder.glob('*.swift')
            for name in re.findall(r'\bclass\s+(\w+)\s*:\s*XCTestCase\b', source.read_text())}


def parse_catalog(text):
    methods = []
    for line in text.splitlines():
        match = re.fullmatch(r'([A-Za-z_]\w*\.[A-Za-z_]\w*)/([A-Za-z_]\w*)(?:\(\))?', line.strip())
        if match: methods.append(match[1] + '/' + match[2])
    if not methods: raise ValueError('No XCTest methods discovered; empty or unsupported swift test list output')
    if len(set(methods)) != len(methods): raise ValueError('Duplicate XCTest method in discovery')
    return sorted(methods)


def verify_execution(text, expected):
    started, finished = [], []
    for owner, method, status in re.findall(r"^Test Case '-\[([^ ]+) ([^\]]+)\]' (started|passed|failed|skipped)\b", text, re.M):
        name = owner + '/' + method
        if status in ('failed', 'skipped'): raise ValueError('Mandatory XCTest ' + status + ': ' + name)
        (started if status == 'started' else finished).append(name)
    expected = Counter(expected)
    for label, actual in [('started', started), ('passed', finished)]:
        observed = Counter(actual)
        if observed != expected:
            raise ValueError('Incomplete XCTest ' + label + '; missing=' + repr(list((expected-observed).elements())) + '; unexpected/duplicate=' + repr(list((observed-expected).elements())))
    targets = Counter(name.split('.')[0] for name in finished)
    return dict(expected=sum(expected.values()), executed=len(finished), byTarget=dict(sorted(targets.items())),
                catalogSHA256=hashlib.sha256('\n'.join(sorted(expected)).encode()).hexdigest())


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--catalog', type=Path, required=True)
    options = parser.parse_args()
    try:
        methods = parse_catalog(options.catalog.read_text())
        proof = check_classes({name.split('/')[0] for name in methods}, json.loads(options.manifest.read_text()))
        print(json.dumps(dict(methods=len(methods), **proof), indent=2))
    except (ValueError, OSError) as error:
        print('CONTRACT ERROR: ' + str(error)); raise SystemExit(1)
