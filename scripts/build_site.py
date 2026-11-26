#!/usr/bin/env python3
"""Build the publication from JSON; optionally refresh its generated Git views."""
# SPDX-License-Identifier: MIT
from __future__ import annotations

import argparse
import os
from pathlib import Path

from patchthese.publishing import build_site
from patchthese.validation import ValidationError


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write-generated", action="store_true", help="Refresh generated digest Markdown and the README edition block.")
    parser.add_argument("--check", action="store_true", help="Fail if the committed digest Markdown or README edition block differs from what the JSON generates.")
    parser.add_argument("--site-url", default=os.getenv("SITE_URL", "https://jluethe.github.io/patch-these"), help="Canonical public URL, including the project path.")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    try:
        result = build_site(root, site_url=args.site_url, write_generated=args.write_generated, check_generated=args.check)
    except (ValidationError, ValueError) as exc:
        parser.exit(1, f"Build failed: {exc}\n")
    print(f"Built {result} from data/*.json.")


if __name__ == "__main__":
    main()
