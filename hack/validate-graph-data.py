#!/usr/bin/env python3
"""Validate Cincinnati graph data files.

Checks the schema `version` file and every file in channels/ and
blocked-edges/:

* YAML parses with the safe loader and matches the expected schema.
* Channel names match their filenames, and versions are valid Semantic
  Versions with no duplicates.
* Blocked-edge `to` entries are valid Semantic Versions.
* Blocked-edge `from` patterns compile, avoid nested quantifiers (a
  catastrophic-backtracking risk for every graph-data consumer), and
  match known version strings within a time limit where the platform
  supports interval timers.

Prints each problem and exits non-zero on failure, so it can run as a
local check or a CI presubmit.  Run from the repository root, or point
--root at one.
"""

import argparse
import os
import re
import signal
import sys

import yaml


_VERSION_REGEXP = re.compile('^(?P<major>0|[1-9]\d*)\.(?P<minor>0|[1-9]\d*)\.(?P<patch>0|[1-9]\d*)(?:-(?P<prerelease>(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+(?P<buildmetadata>[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$')
_QUANTIFIERS = frozenset('*+{')
_MATCH_TIMEOUT_SECONDS = 1.0


def _scan_regex(pattern):
    """Yield (index, char) over pattern, skipping escaped chars and reporting a
    flag for whether the current position is inside a [...] character class, so
    callers can reason about regex structure without misreading class or escaped
    literals as metacharacters."""
    i = 0
    in_class = False
    while i < len(pattern):
        char = pattern[i]
        if char == '\\':
            i += 2
            continue
        if in_class:
            if char == ']':
                in_class = False
            i += 1
            continue
        if char == '[':
            in_class = True
            i += 1
            continue
        yield i, char
        i += 1


def _body_has_alternation_or_quantifier(body):
    for _, char in _scan_regex(body):
        if char == '|' or char in _QUANTIFIERS:
            return True
    return False


def risky_quantified_group(pattern):
    """Return True when pattern contains a group that is itself quantified and
    whose body holds an alternation or another quantifier -- the shape behind
    catastrophic backtracking (e.g. (a+)+, (a|a)*, ((a+))+, (a|ab)*).  A group
    with an alternation that is not quantified (e.g. 4\\.1\\.(18|20)) is safe and
    is not flagged."""
    stack = []
    chars = list(_scan_regex(pattern))
    for order, (index, char) in enumerate(chars):
        if char == '(':
            stack.append(index)
        elif char == ')' and stack:
            open_index = stack.pop()
            # A quantifier applies only if it sits immediately after the ')'.
            following = pattern[index + 1] if index + 1 < len(pattern) else ''
            if following in _QUANTIFIERS:
                body = pattern[open_index + 1:index]
                if _body_has_alternation_or_quantifier(body):
                    return True
    return False


def match_with_timer(pattern, text, seconds=_MATCH_TIMEOUT_SECONDS):
    if not hasattr(signal, 'setitimer'):
        return pattern.match(text)

    def handle(signum, frame):
        raise TimeoutError('matching {!r} against {!r} took more than {} seconds'.format(pattern.pattern, text, seconds))

    previous = signal.signal(signal.SIGALRM, handle)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        return pattern.match(text)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def data_files(directory, errors):
    for entry in sorted(os.listdir(directory)):
        path = os.path.join(directory, entry)
        if entry == 'OWNERS' or not os.path.isfile(path):
            continue
        if not entry.endswith('.yaml'):
            errors.append('{}: unexpected non-YAML file'.format(path))
            continue
        with open(path) as f:
            try:
                data = yaml.load(f, Loader=yaml.SafeLoader)
            except yaml.YAMLError as error:
                errors.append('{}: failed to load YAML: {}'.format(path, error))
                continue
        yield path, entry, data


def validate_channels(directory, errors):
    versions = set()
    count = 0
    for path, entry, data in data_files(directory, errors):
        count += 1
        if not isinstance(data, dict) or set(data) != {'name', 'versions'}:
            errors.append('{}: expected exactly the keys name and versions, got {}'.format(path, sorted(data) if isinstance(data, dict) else type(data).__name__))
            continue
        if data['name'] != os.path.splitext(entry)[0]:
            errors.append('{}: name {!r} must match the filename'.format(path, data['name']))
        if not isinstance(data['versions'], list):
            errors.append('{}: versions must be a list, got {}'.format(path, type(data['versions']).__name__))
            continue
        seen = set()
        for version in data['versions']:
            if not isinstance(version, str) or not _VERSION_REGEXP.match(version):
                errors.append('{}: version {!r} is not a valid Semantic Version'.format(path, version))
                continue
            if version in seen:
                errors.append('{}: duplicate version {}'.format(path, version))
            seen.add(version)
            versions.add(version)
    return versions, count


def validate_blocked_edges(directory, versions, errors):
    sample_texts = sorted(versions) + ['4.' + '1' * 64 + '.99999-not.a.real.version+aaaaaaaa']
    count = 0
    for path, _, data in data_files(directory, errors):
        count += 1
        if not isinstance(data, dict) or set(data) != {'to', 'from'}:
            errors.append('{}: expected exactly the keys to and from, got {}'.format(path, sorted(data) if isinstance(data, dict) else type(data).__name__))
            continue
        if not isinstance(data['to'], str) or not _VERSION_REGEXP.match(data['to']):
            errors.append('{}: to {!r} is not a valid Semantic Version'.format(path, data['to']))
        if not isinstance(data['from'], str):
            errors.append('{}: from must be a string, got {}'.format(path, type(data['from']).__name__))
            continue
        try:
            pattern = re.compile(data['from'])
        except re.error as error:
            errors.append('{}: from pattern {!r} does not compile: {}'.format(path, data['from'], error))
            continue
        if risky_quantified_group(data['from']):
            errors.append('{}: from pattern {!r} quantifies a group containing an alternation or quantifier, risking catastrophic backtracking'.format(path, data['from']))
            continue
        for text in sample_texts:
            try:
                match_with_timer(pattern, text)
            except TimeoutError as error:
                errors.append('{}: {}'.format(path, error))
                break
    return count


def validate_schema_version(path, errors):
    with open(path) as f:
        schema_version = f.read().strip()
    if not _VERSION_REGEXP.match(schema_version):
        errors.append('{}: schema version {!r} is not a valid Semantic Version'.format(path, schema_version))


def main():
    parser = argparse.ArgumentParser(description='Validate channel and blocked-edge graph data files.')
    parser.add_argument('--root', default='.', help='Repository root to validate (default: current directory).')
    args = parser.parse_args()

    errors = []
    validate_schema_version(os.path.join(args.root, 'version'), errors)
    versions, channel_count = validate_channels(os.path.join(args.root, 'channels'), errors)
    blocked_edge_count = validate_blocked_edges(os.path.join(args.root, 'blocked-edges'), versions, errors)

    for error in errors:
        print('ERROR: {}'.format(error))
    if errors:
        return 1
    print('validated {} channel files ({} versions) and {} blocked-edge files'.format(channel_count, len(versions), blocked_edge_count))
    return 0


if __name__ == '__main__':
    sys.exit(main())
