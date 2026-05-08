#!/usr/bin/env bash
set -e

echo "Installing Python dependencies..."
python3 -m pip install --user -r requirements.txt
python3 -m pip install --user -e .

echo ""
echo "Checking for external tools..."

declare -A TOOLS=(
  [nuclei]="brew install nuclei  OR  go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
  [nmap]="brew install nmap"
  [subfinder]="brew install subfinder"
  [httpx]="brew install httpx"
  [docker]="https://docs.docker.com/get-docker/  (needed for OWASP ZAP)"
  [trivy]="brew install trivy"
  [semgrep]="brew install semgrep"
  [gitleaks]="brew install gitleaks"
  [ffuf]="brew install ffuf"
)

MISSING=0
for tool in "${!TOOLS[@]}"; do
  if command -v "$tool" >/dev/null 2>&1; then
    echo "  [ok] $tool"
  else
    echo "  [missing] $tool   install: ${TOOLS[$tool]}"
    MISSING=$((MISSING + 1))
  fi
done

echo ""
if [ "$MISSING" -gt 0 ]; then
  echo "$MISSING tools missing. Install them above to enable all scanners."
  echo "secscan will skip scanners whose tools are missing."
else
  echo "All tools installed."
fi

echo ""
echo "Run: secscan --help"
