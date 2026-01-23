#!/usr/bin/env python3

import json
import sys


def load_maintainers(filepath):
    with open(filepath) as f:
        return json.load(f)


def paths_for_reviewer(data, reviewer):
    paths = []
    for entry in data['entries']:
        if reviewer in entry['reviewers']:
            paths.extend(entry['paths'])
    return paths


def reviewers_for_paths(data, query_paths):
    reviewers = set()
    for entry in data['entries']:
        for path in entry['paths']:
            for query_path in query_paths:
                if query_path.startswith(path) or path.startswith(query_path):
                    reviewers.update(entry['reviewers'])
                    break
    return sorted(reviewers)


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Usage: maintainers.py <MAINTAINERS.json> <command> [args...]")
        print("  reviewer <name>       - list paths for reviewer")
        print("  paths <path>...       - list reviewers for paths")
        sys.exit(1)

    data = load_maintainers(sys.argv[1])
    if data.get('version') != 1:
        print(f"Unsupported MAINTAINERS.json version: {data.version}")
        sys.exit(1)
    cmd = sys.argv[2]

    if len(sys.argv) < 3:
        print("Usage: maintainers.py <file> <path>...")
        sys.exit(1)
    reviewers = reviewers_for_paths(data, sys.argv[2:])
    if len(reviewers) == 0:
        print("No reviewers found")
        sys.exit(1)
    print(reviewers)
