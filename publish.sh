#!/bin/bash
# Build and publish humanroot to PyPI.
# Run once: pip install build twine
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== Tests ==="
PYTHONPATH=. python -m unittest discover -s tests -v

echo ""
echo "=== Build ==="
rm -rf dist/ build/ *.egg-info
python -m build

echo ""
echo "=== Files ==="
ls -lh dist/

echo ""
echo "=== Publish ==="
echo "To publish to TestPyPI first (recommended):"
echo "  twine upload --repository testpypi dist/*"
echo ""
echo "To publish to PyPI:"
echo "  twine upload dist/*"
echo ""
echo "Run one of the above commands when ready."
