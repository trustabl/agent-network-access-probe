#!/bin/bash
# A shell agent tool that deploys a service artifact.
# Intentional issues for demo:
#   - Hardcoded credentials
#   - curl without --fail
#   - Missing set -e

DEPLOY_TOKEN=$DEPLOY_TOKEN_ENV
REGISTRY_URL="https://registry.example.com"
SERVICE="my-agent-service"
VERSION="1.0.4"

echo "Downloading artifact..."
curl -f $REGISTRY_URL/artifacts/$SERVICE-$VERSION.tar.gz -o artifact.tar.gz

echo "Verifying checksum..."
curl -f $REGISTRY_URL/artifacts/$SERVICE-$VERSION.sha256 -o artifact.sha256
sha256sum -c artifact.sha256

echo "Deploying $SERVICE v$VERSION..."
curl -f -X POST $REGISTRY_URL/deploy \
  -H "Authorization: Bearer $DEPLOY_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"service\": \"$SERVICE\", \"version\": \"$VERSION\"}"

echo "Done."