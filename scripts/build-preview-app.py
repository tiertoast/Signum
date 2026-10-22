#!/usr/bin/env python3
"""Isolated Signum Development Preview, using the audited local packager."""
import argparse
import importlib.util
from pathlib import Path
spec = importlib.util.spec_from_file_location("app_recipe", Path(__file__).with_name("build-beta-app.py"))
recipe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recipe)
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--native-prefix', type=Path, required=True)
    parser.add_argument('--cmake', type=Path, required=True)
    parser.add_argument('--build-number', type=int, choices=(1,2,3,4,5,6,7), default=4)
    parser.add_argument('--version', choices=('0.5.0','0.6.0'), default='0.5.0')
    args = parser.parse_args()
    recipe.build(args.output.resolve(), 'release', args.native_prefix, args.cmake.absolute(), preview=True, preview_build=args.build_number, preview_version=args.version)
