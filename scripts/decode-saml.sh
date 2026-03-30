#!/bin/bash
# Usage: ./decode-saml.sh <SAMLResponse value>
# Or pipe it: echo "<value>" | ./decode-saml.sh

if [ -t 0 ] && [ -z "$1" ]; then
  echo "Usage: ./decode-saml.sh <SAMLResponse>"
  echo "   or: echo '<value>' | ./decode-saml.sh"
  exit 1
fi

input="${1:-$(cat)}"

python3 -c "
import sys, base64, urllib.parse, xml.dom.minidom

raw = sys.argv[1].strip()
decoded = base64.b64decode(urllib.parse.unquote(raw))
pretty = xml.dom.minidom.parseString(decoded).toprettyxml(indent='  ')
# Remove the redundant XML declaration line
lines = pretty.split('\n')
print('\n'.join(lines[1:] if lines[0].startswith('<?xml') else lines))
" "$input"
