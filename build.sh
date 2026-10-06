#!/usr/bin/env zsh
set -e

VERSION="0.1.0"
DIST="dist"
MODULE="./cmd/autofix/"

for arg in "$@"; do
  case $arg in
    --no-obfuscate|--obfuscate) ;;
    *) VERSION=$arg ;;
  esac
done

echo "Building autofix v${VERSION}..."

rm -rf "$DIST" && mkdir -p "$DIST"

build() {
  local goos=$1 goarch=$2 os_arch=$3 ext=${4:-""}
  echo "  → ${os_arch}"

  GOOS=$goos GOARCH=$goarch CGO_ENABLED=0 GOWORK=off \
    go build -trimpath \
    -ldflags "-X main.version=${VERSION} -s -w" \
    -o "$DIST/autofix${ext}" \
    "$MODULE"

  if [[ -n "$ext" ]]; then
    (cd "$DIST" && zip -q "autofix_${VERSION}_${os_arch}.zip" "autofix${ext}" && rm "autofix${ext}")
  else
    (cd "$DIST" && tar czf "autofix_${VERSION}_${os_arch}.tar.gz" "autofix" && rm "autofix")
  fi
}

build linux   amd64 linux_amd64
build darwin  amd64 darwin_amd64
build darwin  arm64 darwin_arm64
build windows amd64 windows_amd64 .exe

echo "\nGenerating checksums..."
(cd "$DIST" && sha256sum autofix_* > checksums.txt)

HASH_LINUX=$(grep linux_amd64.tar.gz    "$DIST/checksums.txt" | awk '{print $1}')
HASH_MAC_AMD=$(grep darwin_amd64.tar.gz "$DIST/checksums.txt" | awk '{print $1}')
HASH_MAC_ARM=$(grep darwin_arm64.tar.gz "$DIST/checksums.txt" | awk '{print $1}')
HASH_WIN=$(grep windows_amd64.zip       "$DIST/checksums.txt" | awk '{print $1}')

BASE_URL="https://github.com/trustabl/agent-network-access-probe/releases/download/v${VERSION}"

cat > "$DIST/autofix.rb" <<FORMULA
class Autofix < Formula
  desc "Network egress evidence and least-privilege OpenShell policy for agent tools"
  homepage "https://github.com/trustabl/agent-network-access-probe"
  version "${VERSION}"
  license "Apache-2.0"

  on_macos do
    on_arm do
      url "${BASE_URL}/autofix_${VERSION}_darwin_arm64.tar.gz"
      sha256 "${HASH_MAC_ARM}"
    end
    on_intel do
      url "${BASE_URL}/autofix_${VERSION}_darwin_amd64.tar.gz"
      sha256 "${HASH_MAC_AMD}"
    end
  end

  on_linux do
    on_intel do
      url "${BASE_URL}/autofix_${VERSION}_linux_amd64.tar.gz"
      sha256 "${HASH_LINUX}"
    end
  end

  def install
    bin.install "autofix"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/autofix version")
  end
end
FORMULA

cat > "$DIST/autofix.json" <<MANIFEST
{
  "version": "${VERSION}",
  "description": "Network egress evidence and least-privilege OpenShell policy for agent tools",
  "homepage": "https://github.com/trustabl/agent-network-access-probe",
  "license": "Apache-2.0",
  "architecture": {
    "64bit": {
      "url": "${BASE_URL}/autofix_${VERSION}_windows_amd64.zip",
      "hash": "${HASH_WIN}"
    }
  },
  "bin": "autofix.exe",
  "checkver": {
    "github": "https://github.com/trustabl/agent-network-access-probe"
  },
  "autoupdate": {
    "architecture": {
      "64bit": {
        "url": "https://github.com/trustabl/agent-network-access-probe/releases/download/v\$version/autofix_\$version_windows_amd64.zip"
      }
    }
  }
}
MANIFEST

echo "\nDone. Artifacts in ./${DIST}/:"
ls -lh "$DIST"
echo "\nNext step:"
echo "  gh release create v${VERSION} dist/autofix_* dist/checksums.txt \\"
echo "    --repo trustabl/agent-network-access-probe --title \"autofix v${VERSION}\" --notes \"Initial release\""
