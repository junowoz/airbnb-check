#!/bin/sh
# airbnb-check launcher. Works from a clone (./run.sh) and piped:
#   curl -fsSL https://raw.githubusercontent.com/junowoz/airbnb-check/main/run.sh | sh
#   curl -fsSL https://raw.githubusercontent.com/junowoz/airbnb-check/main/run.sh | sh -s -- --report
# It installs nothing: it works in a private temp folder (source when piped, vendor-name cache always) and deletes it.
# The tool only reads your own network (no logins, no writes) and uses just the Python standard library.
#
# Everything lives in main() and main is called on the last line: a truncated download never runs half a script.

main() {
  set -u
  umask 077
  URL="https://codeload.github.com/junowoz/airbnb-check/tar.gz/refs/heads/main"

  # Pick Python: Apple's on macOS (the only one allowed to read MAC addresses), python3 >= 3.9 elsewhere.
  if [ "$(uname -s)" = "Darwin" ]; then
    py=/usr/bin/python3
    if [ ! -x "$py" ] || ! xcode-select -p >/dev/null 2>&1; then
      echo "airbnb-check needs Python 3 from the Xcode Command Line Tools." >&2
      echo "Install them once with:  xcode-select --install   then run this command again." >&2
      return 1
    fi
  else
    py=$(command -v python3 || true)
  fi
  if [ -z "${py:-}" ] || ! "$py" -c 'import sys; sys.exit(sys.version_info < (3, 9))' 2>/dev/null; then
    echo "airbnb-check needs Python 3.9 or newer (python3 not found or too old)." >&2
    return 1
  fi

  # One private temp folder; always removed, also on Ctrl-C or kill.
  tmp=$(mktemp -d "${TMPDIR:-/tmp}/airbnb-check.XXXXXX") || return 1
  trap 'rm -rf "$tmp"' EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM

  # From a clone: run in place.
  src=
  piped=1
  case "$0" in
    run.sh|*/run.sh)
      here=$(cd "$(dirname "$0")" 2>/dev/null && pwd) || here=
      if [ -n "$here" ] && [ -f "$here/src/airbnb_check/__main__.py" ]; then
        src="$here/src"
        piped=0
      fi
      ;;
  esac

  # Piped: download over HTTPS only.
  if [ "$piped" = 1 ]; then
    echo "Downloading airbnb-check (kept only in $tmp until it finishes)..." >&2
    if command -v curl >/dev/null 2>&1; then
      curl -fsSL --proto '=https' --proto-redir '=https' --tlsv1.2 --connect-timeout 15 --max-time 180 \
        --max-filesize 20000000 "$URL" -o "$tmp/src.tgz"
    elif command -v wget >/dev/null 2>&1; then
      wget -q --https-only --max-redirect=5 -T 30 -t 2 -O "$tmp/src.tgz" "$URL"
    else
      echo "Need curl or wget to download airbnb-check." >&2
      return 1
    fi || { echo "Download failed (check your internet connection and the URL: $URL)." >&2; return 1; }
    mkdir "$tmp/app" && tar -xzf "$tmp/src.tgz" -C "$tmp/app" --strip-components=1 \
      && [ -f "$tmp/app/src/airbnb_check/__main__.py" ] \
      || { echo "Could not unpack the download." >&2; return 1; }
    src="$tmp/app/src"
  fi

  # Only our code on the path, no bytecode written next to it, vendor-name cache inside the temp folder.
  unset PYTHONHOME PYTHONSTARTUP PYTHONINSPECT
  export AIRBNB_CHECK_CACHE="$tmp/cache" PYTHONPATH="$src"
  # Not exec: the shell must stay alive so the trap can delete the temp dir.
  # Piped: stdin is the script itself, so Python gets /dev/null.
  if [ "$piped" = 1 ]; then
    "$py" -B -s -m airbnb_check "$@" </dev/null
  else
    "$py" -B -s -m airbnb_check "$@"
  fi
  return $?
}

main "$@"
exit $?
