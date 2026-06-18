#!/usr/bin/env bash
# Simulated deployment step for the CD pipeline.
#
# There is no real deployment target for this assessment (no hosted
# backend/frontend yet), so this script stands in for whatever a real
# deploy would do at each environment: pull the released artifact, apply
# environment-specific config, restart the service, run a health check.
# Replace the body below with real commands (e.g. ssh+systemctl, `flyctl
# deploy`, `kubectl apply`, a frontend host's CLI) once there's an actual
# target; the CD workflow's job structure (build -> dev -> stage -> prod)
# does not need to change when that happens.
set -euo pipefail

ENVIRONMENT="${1:?usage: deploy.sh <dev|stage|prod> [component]}"
COMPONENT="${2:-backend}"
VERSION="${GITHUB_SHA:-local}"

echo "==> Deploying ${COMPONENT} to '${ENVIRONMENT}' (version ${VERSION})"
echo "    [simulated] pulling build artifact for ${VERSION}"
echo "    [simulated] applying ${ENVIRONMENT} configuration"
echo "    [simulated] restarting ${COMPONENT} service in ${ENVIRONMENT}"
echo "    [simulated] running post-deploy health check"
echo "==> ${COMPONENT} deployment to '${ENVIRONMENT}' complete (version ${VERSION})"
