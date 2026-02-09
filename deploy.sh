#!/bin/bash

set -e

echo "================================================"
echo "QuantumZero Issuer App Deployment Script"
echo "================================================"
echo ""

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo -e "${RED}✗ Docker is not running. Please start Docker and try again.${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Docker is running${NC}"

# Detect host IP for public agent URL (used in mobile invitations)
if [ -z "${QZ_PUBLIC_AGENT_URL:-}" ]; then
    HOST_IP=$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if ($i=="src") {print $(i+1); exit}}')
    if [ -n "$HOST_IP" ]; then
        export QZ_PUBLIC_AGENT_URL="http://${HOST_IP}:8002"
        echo -e "${GREEN}✓ Using host IP for QZ_PUBLIC_AGENT_URL: ${QZ_PUBLIC_AGENT_URL}${NC}"
    else
        echo -e "${YELLOW}⚠ Unable to detect host IP. Set QZ_PUBLIC_AGENT_URL manually if mobile cannot connect.${NC}"
    fi
else
    echo -e "${GREEN}✓ Using QZ_PUBLIC_AGENT_URL from environment: ${QZ_PUBLIC_AGENT_URL}${NC}"
fi

# Check if quantumzero-network exists
if ! docker network inspect quantumzero-network > /dev/null 2>&1; then
    echo -e "${YELLOW}⚠ Network 'quantumzero-network' not found.${NC}"
    echo "This network should be created when QuantumZero Server is deployed."
    echo "Creating network now..."
    docker network create quantumzero-network
    echo -e "${GREEN}✓ Network created${NC}"
else
    echo -e "${GREEN}✓ Network 'quantumzero-network' exists${NC}"
fi

# Check if QuantumZero Server is running
echo ""
echo "Checking QuantumZero Server status..."
if curl -s http://localhost:8081/api/v1/health > /dev/null 2>&1; then
    echo -e "${GREEN}✓ Issuance API is reachable${NC}"
else
    echo -e "${YELLOW}⚠ Issuance API is not reachable at http://localhost:8081${NC}"
    echo "Make sure QuantumZero Server is deployed and running."
    echo "Continue anyway? (y/n)"
    read -r response
    if [[ ! "$response" =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Build the Docker image
echo ""
echo "Building issuer app Docker image..."
docker compose build

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Build successful${NC}"
else
    echo -e "${RED}✗ Build failed${NC}"
    exit 1
fi

# Start the service
echo ""
echo "Starting issuer app..."
docker compose up -d

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Issuer app started${NC}"
else
    echo -e "${RED}✗ Failed to start issuer app${NC}"
    exit 1
fi

# Wait for the service to be ready
echo ""
echo "Waiting for issuer app to be ready..."
for i in {1..30}; do
    if curl -s http://localhost:8090 > /dev/null 2>&1; then
        echo -e "${GREEN}✓ Issuer app is ready${NC}"
        break
    fi
    if [ $i -eq 30 ]; then
        echo -e "${RED}✗ Issuer app failed to start within 30 seconds${NC}"
        echo "Check logs with: docker compose logs issuer-app"
        exit 1
    fi
    echo -n "."
    sleep 1
done

# Display summary
echo ""
echo "================================================"
echo -e "${GREEN}Deployment Complete!${NC}"
echo "================================================"
echo ""
echo "Access Points:"
echo "  Issuer Portal: http://localhost:8090"
echo ""
echo "QuantumZero Server APIs:"
echo "  Admin API:        http://localhost:8080"
echo "  Issuance API:     http://localhost:8081"
echo "  Revocation API:   http://localhost:8082"
echo "  Verification API: http://localhost:8083"
echo "  Web Frontend:     http://localhost:3000"
echo ""
echo "Useful Commands:"
echo "  View logs:     docker compose logs -f issuer-app"
echo "  Stop service:  docker compose down"
echo "  Restart:       docker compose restart"
echo ""
echo "Next Steps:"
echo "  1. Open http://localhost:8090 in your browser"
echo "  2. Create an issuer DID"
echo "  3. Register the issuer"
echo "  4. Create schemas and credential definitions"
echo "  5. Issue credentials"
echo ""
echo "Note: Issuer registration and requests require admin approval"
echo "      via the Web Frontend at http://localhost:3000"
echo ""
