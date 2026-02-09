# QuantumZero Issuer App Deployment Script
# PowerShell version for Windows

Write-Host "================================================" -ForegroundColor Cyan
Write-Host "QuantumZero Issuer App Deployment Script" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""

# Check if Docker is running
try {
    docker info | Out-Null
    Write-Host "✓ Docker is running" -ForegroundColor Green

    # Detect host IP for public agent URL (used in mobile invitations)
    if (-not $env:QZ_PUBLIC_AGENT_URL -or $env:QZ_PUBLIC_AGENT_URL.Trim() -eq '') {
        try {
            $defaultRoute = Get-NetRoute -DestinationPrefix "0.0.0.0/0" | Sort-Object -Property RouteMetric | Select-Object -First 1
            $ip = (Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $defaultRoute.InterfaceIndex |
                Where-Object { $_.IPAddress -ne '127.0.0.1' } | Select-Object -First 1).IPAddress
            if ($ip) {
                $env:QZ_PUBLIC_AGENT_URL = "http://$ip:8002"
                Write-Host "✓ Using host IP for QZ_PUBLIC_AGENT_URL: $env:QZ_PUBLIC_AGENT_URL" -ForegroundColor Green
            } else {
                Write-Host "⚠ Unable to detect host IP. Set QZ_PUBLIC_AGENT_URL manually if mobile cannot connect." -ForegroundColor Yellow
            }
        } catch {
            Write-Host "⚠ Unable to detect host IP. Set QZ_PUBLIC_AGENT_URL manually if mobile cannot connect." -ForegroundColor Yellow
        }
    } else {
        Write-Host "✓ Using QZ_PUBLIC_AGENT_URL from environment: $env:QZ_PUBLIC_AGENT_URL" -ForegroundColor Green
    }
} catch {
    Write-Host "✗ Docker is not running. Please start Docker and try again." -ForegroundColor Red
    exit 1
}

# Check if quantumzero-network exists
try {
    docker network inspect quantumzero-network | Out-Null
    Write-Host "✓ Network 'quantumzero-network' exists" -ForegroundColor Green
} catch {
    Write-Host "⚠ Network 'quantumzero-network' not found." -ForegroundColor Yellow
    Write-Host "This network should be created when QuantumZero Server is deployed."
    Write-Host "Creating network now..."
    docker network create quantumzero-network
    Write-Host "✓ Network created" -ForegroundColor Green
}

# Check if QuantumZero Server is running
Write-Host ""
Write-Host "Checking QuantumZero Server status..."
try {
    $response = Invoke-WebRequest -Uri "http://localhost:8081/api/v1/health" -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
    Write-Host "✓ Issuance API is reachable" -ForegroundColor Green
} catch {
    Write-Host "⚠ Issuance API is not reachable at http://localhost:8081" -ForegroundColor Yellow
    Write-Host "Make sure QuantumZero Server is deployed and running."
    $response = Read-Host "Continue anyway? (y/n)"
    if ($response -notmatch '^[Yy]$') {
        exit 1
    }
}

# Build the Docker image
Write-Host ""
Write-Host "Building issuer app Docker image..."
docker-compose build

if ($LASTEXITCODE -eq 0) {
    Write-Host "✓ Build successful" -ForegroundColor Green
} else {
    Write-Host "✗ Build failed" -ForegroundColor Red
    exit 1
}

# Start the service
Write-Host ""
Write-Host "Starting issuer app..."
docker-compose up -d

if ($LASTEXITCODE -eq 0) {
    Write-Host "✓ Issuer app started" -ForegroundColor Green
} else {
    Write-Host "✗ Failed to start issuer app" -ForegroundColor Red
    exit 1
}

# Wait for the service to be ready
Write-Host ""
Write-Host "Waiting for issuer app to be ready..."
$ready = $false
for ($i = 1; $i -le 30; $i++) {
    try {
        $response = Invoke-WebRequest -Uri "http://localhost:8090" -UseBasicParsing -TimeoutSec 2 -ErrorAction Stop
        Write-Host "✓ Issuer app is ready" -ForegroundColor Green
        $ready = $true
        break
    } catch {
        Write-Host "." -NoNewline
        Start-Sleep -Seconds 1
    }
}

if (-not $ready) {
    Write-Host ""
    Write-Host "✗ Issuer app failed to start within 30 seconds" -ForegroundColor Red
    Write-Host "Check logs with: docker-compose logs issuer-app"
    exit 1
}

# Display summary
Write-Host ""
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "Deployment Complete!" -ForegroundColor Green
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Access Points:" -ForegroundColor Cyan
Write-Host "  Issuer Portal: http://localhost:8090"
Write-Host ""
Write-Host "QuantumZero Server APIs:" -ForegroundColor Cyan
Write-Host "  Admin API:        http://localhost:8080"
Write-Host "  Issuance API:     http://localhost:8081"
Write-Host "  Revocation API:   http://localhost:8082"
Write-Host "  Verification API: http://localhost:8083"
Write-Host "  Web Frontend:     http://localhost:3000"
Write-Host ""
Write-Host "Useful Commands:" -ForegroundColor Cyan
Write-Host "  View logs:     docker-compose logs -f issuer-app"
Write-Host "  Stop service:  docker-compose down"
Write-Host "  Restart:       docker-compose restart"
Write-Host ""
Write-Host "Next Steps:" -ForegroundColor Cyan
Write-Host "  1. Open http://localhost:8090 in your browser"
Write-Host "  2. Create an issuer DID"
Write-Host "  3. Register the issuer"
Write-Host "  4. Create schemas and credential definitions"
Write-Host "  5. Issue credentials"
Write-Host ""
Write-Host "Note: Issuer registration and requests require admin approval" -ForegroundColor Yellow
Write-Host "      via the Web Frontend at http://localhost:3000" -ForegroundColor Yellow
Write-Host ""
