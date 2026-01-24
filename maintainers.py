#!/usr/bin/env python3

import json
import sys
from pathlib import Path


def load_maintainers(filepath: Path):
    with open(filepath) as f:
        data = json.load(f)
        if data.get('version') != 1:
            print(f"Unsupported MAINTAINERS.json version: {data.version}")
            sys.exit(1)

        src = filepath.parent.resolve()
        # Do some basic validation:
        # - each entry has a unique name, a non-empty set of paths, and a
        #   non-empty set of reviewers,
        # - each path is either a file or directory in the src tree, or a glob
        #   matching at least one file.
        for entry in data['entries']:
            if 'name' not in entry or not entry['name']:
                raise ValueError("Each entry must have a non-empty name")
            if 'paths' not in entry or not entry['paths']:
                raise ValueError(f"Entry {entry['name']} must have at least one path")
            if 'reviewers' not in entry or not entry['reviewers']:
                raise ValueError(f"Entry {entry['name']} must have at least one reviewer")
            for path in entry['paths'] + entry.get('exclusions', []):
                full_path = src / path
                if '*' in path or '?' in path or '[' in path:
                    matches = list(src.glob(path))
                    if not matches:
                        raise ValueError(f"Glob pattern '{path}' in entry '{entry['name']}' does not match any files")
                else:
                    if not full_path.exists():
                        raise ValueError(f"Path '{path}' in entry '{entry['name']}' does not exist in source tree")
        return data


def match(path: Path, pattern):
    if any(path.glob(pattern)):
        return True
    if path.is_relative_to(pattern):
        return True
    return False


def reviewers_for_paths(data, query_paths):
    """Given a list of filles, return the union of all matching reviewers."""
    reviewers = set()
    for entry in data['entries']:
        for path in entry['paths']:
            for query_path in query_paths:
                if match(query_path, path):
                    for exclusion in entry.get('exclusions', []):
                        if match(query_path, exclusion):
                            break
                    else:
                        reviewers.update(entry['reviewers'])

    return sorted(reviewers)


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Usage: maintainers.py <MAINTAINERS.json> <path> [<paths> ...]")
        sys.exit(1)

    file = Path(sys.argv[1])
    data = load_maintainers(file)
    cmd = sys.argv[2]

    if len(sys.argv) < 3:
        print("Usage: maintainers.py <file> <path>...")
        sys.exit(1)

    paths = [Path(p) for p in sys.argv[2:]]
    for path in paths:
        if not (file.parent / path).exists():
            print(f"Error: path '{path}' does not exist in source tree")
            sys.exit(1)
    reviewers = reviewers_for_paths(data, [Path(p) for p in sys.argv[2:]])
    if len(reviewers) == 0:
        print("No reviewers found")
        sys.exit(1)
    print(reviewers)
