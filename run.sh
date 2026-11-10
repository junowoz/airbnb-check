#!/bin/sh
# Run airbnb-check straight from a clone: no install, no setup.
here=$(cd "$(dirname "$0")" && pwd)
py=python3
if [ "$(uname -s)" = "Darwin" ] && [ -x /usr/bin/python3 ]; then
  py=/usr/bin/python3  # Apple's Python can read MAC addresses (Local Network privacy)
fi
PYTHONPATH="$here/src${PYTHONPATH:+:$PYTHONPATH}" exec "$py" -m airbnb_check "$@"
