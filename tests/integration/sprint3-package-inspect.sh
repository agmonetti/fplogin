#!/bin/sh
# Archive-only verifier; see --help for required trusted reference/digest inputs.
set -eu
exec python3 "$(dirname "$0")/sprint3-package-inspect.py" "$@"
