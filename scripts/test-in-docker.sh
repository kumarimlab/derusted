#!/bin/bash
# Quick script to build and test Derusted in Docker

set -e

echo "=== Derusted Docker Test Runner ==="
echo ""

# Check if docker is available
if ! command -v docker &> /dev/null; then
    echo "❌ Error: Docker is not installed"
    exit 1
fi

# Check if docker-compose is available
if ! command -v docker-compose &> /dev/null; then
    echo "⚠️  Warning: docker-compose not found, using docker compose"
    DOCKER_COMPOSE="docker compose"
else
    DOCKER_COMPOSE="docker-compose"
fi

echo "Building Docker image..."
$DOCKER_COMPOSE build

echo ""
echo "Running test suite..."
$DOCKER_COMPOSE up --abort-on-container-exit

EXIT_CODE=$?

if [ $EXIT_CODE -eq 0 ]; then
    echo ""
    echo "✅ All tests passed!"
else
    echo ""
    echo "❌ Tests failed with exit code $EXIT_CODE"
fi

# Cleanup
$DOCKER_COMPOSE down

exit $EXIT_CODE
