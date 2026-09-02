#!/usr/bin/env bash
# Build the man pages with both supported toolchains (asciidoctor, and
# classic asciidoc-py via docbook + xsltproc) and compare the rendered
# output, so syntax that only one tool understands — or renders
# differently — cannot creep into the .adoc sources (#2395).
#
# Modeled on git's ci/test-documentation.sh: any warning on stderr from
# either toolchain fails the check.
#
# Requires: asciidoctor, asciidoc, xsltproc, docbook-xsl (registered in
# the XML catalog), man-db.

set -eu

cd "$(dirname "$0")/.."

PAGES="src/rnp/rnp.1.adoc src/rnpkeys/rnpkeys.1.adoc src/lib/librnp.3.adoc"
VERSION="0.0.0-check"

if command -v mandoc >/dev/null 2>&1; then
  render() { mandoc -Tutf8 -Owidth=80 "$1" 2>/dev/null; }
else
  render() { MANWIDTH=80 man --nh --nj -l "$1" 2>/dev/null; }
fi

# The trailing AUTHOR section and page footer are dropped: their exact
# shape (bold author, "Author." subheading, date format) differs between
# the backends without being a content difference. mandoc -Tutf8 renders
# bold via overstruck doubled characters, hence the .? between letters.
normalize() {
  sed -E -e 's#<(https?://[^>]*)>#\1#g' \
      -e '/^[ \t]*(A.AU.UT.TH.HO.OR.R|AUTHOR)[ \t]*$/,$d' \
    | tr -s '[:space:]' ' '
}

# Toolchain noise that does not indicate a documentation problem:
# asciidoc-py < 10.2.1 emits Python SyntaxWarnings from its own config
# on Python 3.12+ (git's ci/test-documentation.sh filters the same).
filter_err() {
  sed -e '/SyntaxWarning: invalid escape sequence/d' "$1"
}

fail=0

for page in $PAGES; do
  name="$(basename "$page" .adoc)"

  asciidoctor -b manpage -a component-version="$VERSION" -o "$name.ad" "$page" 2> "$name.ad.err"
  asciidoc -b docbook -d manpage -a component-version="$VERSION" -o "$name.xml" "$page" 2> "$name.py.err"
  # docbook-xsl names its output after the first NAME refname; run in a
  # scratch dir so it lands on a known path.
  mkdir -p "$name.py.d"
  ( cd "$name.py.d" && xsltproc --nonet ../cmake/Modules/adoc-manpage.xsl "../$name.xml" ) 2> "$name.py.d.err"

  for err in "$name.ad.err" "$name.py.err" "$name.py.d.err"; do
    if [ -n "$(filter_err "$err")" ]; then
      echo "error: $page: $(basename "$err") is not empty:" >&2
      cat "$err" >&2
      fail=1
    fi
  done

  if ! diff -u \
      <(render "$name.ad" | normalize | fold -w 80) \
      <(render "$name.py.d/$name" | normalize | fold -w 80) > "$name.diff"; then
    echo "error: $page renders differently under asciidoctor and asciidoc:" >&2
    cat "$name.diff" >&2
    fail=1
  fi

  rm -rf "$name.ad" "$name.ad.err" "$name.xml" "$name.py.err" "$name.py.d" "$name.py.d.err" "$name.diff"
done

if [ "$fail" -ne 0 ]; then
  exit 1
fi

echo "all man pages build warning-free and render identically with both toolchains"
