#!/usr/bin/env python3
"""Private arm64/macOS 13 dependencies for the 0.5 preview; reuses the beta recipe."""
import argparse
import importlib.util
from pathlib import Path
spec = importlib.util.spec_from_file_location("native_recipe", Path(__file__).with_name("build-beta-native.py"))
recipe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recipe)
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--cmake', type=Path, required=True)
    args = parser.parse_args()
    recipe.build(args.output.resolve(), args.cmake.absolute(), trust=True)
