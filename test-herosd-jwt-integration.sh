#!/bin/bash
set -e

echo "=========================================="
echo "HeroSD-JWT Integration Build & Test Script"
echo "=========================================="
echo ""

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if dotnet is installed
if ! command -v dotnet &> /dev/null; then
    echo -e "${RED}Error: dotnet SDK is not installed${NC}"
    echo "Please install .NET 9.0 SDK from https://dotnet.microsoft.com/download/dotnet/9.0"
    exit 1
fi

echo -e "${GREEN}✓ .NET SDK found${NC}"
dotnet --version
echo ""

# Step 1: Clean previous builds
echo "Step 1: Cleaning previous builds..."
dotnet clean --verbosity quiet
echo -e "${GREEN}✓ Clean completed${NC}"
echo ""

# Step 2: Restore NuGet packages (this will download HeroSD-JWT)
echo "Step 2: Restoring NuGet packages..."
echo "This will download the HeroSD-JWT package from NuGet.org..."
dotnet restore --verbosity normal
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Restore completed successfully${NC}"
else
    echo -e "${RED}✗ Restore failed - HeroSD-JWT package may not be available on NuGet.org yet${NC}"
    echo ""
    echo "If the package is not yet published, you can:"
    echo "1. Wait for the package to be published to NuGet.org"
    echo "2. Temporarily revert to mock implementations"
    exit 1
fi
echo ""

# Step 3: List installed packages to verify HeroSD-JWT
echo "Step 3: Verifying HeroSD-JWT package installation..."
dotnet list src/Libraries/HeroSSID.Credentials/HeroSSID.Credentials.csproj package | grep -i "HeroSD-JWT" || echo -e "${YELLOW}⚠ HeroSD-JWT package not found in list${NC}"
echo ""

# Step 4: Build the solution
echo "Step 4: Building solution..."
dotnet build --configuration Release --no-restore --verbosity normal
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Build completed successfully${NC}"
else
    echo -e "${RED}✗ Build failed${NC}"
    echo ""
    echo "Common issues:"
    echo "- API mismatch with HeroSD-JWT package (check Implementations/*.cs files)"
    echo "- Missing using statements"
    echo "- Incorrect type names from the HeroSD-JWT package"
    exit 1
fi
echo ""

# Step 5: Run unit tests
echo "Step 5: Running unit tests..."
echo ""

echo "5a. Running HeroSSID.Unit.Tests..."
dotnet test tests/Unit/HeroSSID.Unit.Tests/HeroSSID.Unit.Tests.csproj \
    --configuration Release \
    --no-build \
    --verbosity normal \
    --logger "console;verbosity=detailed"
echo ""

echo "5b. Running HeroSSID.Credentials.Tests..."
dotnet test tests/Unit/HeroSSID.Credentials.Tests/HeroSSID.Credentials.Tests.csproj \
    --configuration Release \
    --no-build \
    --verbosity normal \
    --logger "console;verbosity=detailed"
echo ""

echo "5c. Running HeroSSID.DidOperations.Tests..."
dotnet test tests/Unit/HeroSSID.DidOperations.Tests/HeroSSID.DidOperations.Tests.csproj \
    --configuration Release \
    --no-build \
    --verbosity normal \
    --logger "console;verbosity=detailed"
echo ""

echo "5d. Running HeroSSID.Data.Tests..."
dotnet test tests/Unit/HeroSSID.Data.Tests/HeroSSID.Data.Tests.csproj \
    --configuration Release \
    --no-build \
    --verbosity normal \
    --logger "console;verbosity=detailed"
echo ""

# Step 6: Run integration tests
echo "Step 6: Running integration tests..."
dotnet test tests/Integration/HeroSSID.Integration.Tests/HeroSSID.Integration.Tests.csproj \
    --configuration Release \
    --no-build \
    --verbosity normal \
    --logger "console;verbosity=detailed"
echo ""

# Step 7: Run contract tests
echo "Step 7: Running contract tests..."
dotnet test tests/Contract/HeroSSID.DidOperations.Contract.Tests/HeroSSID.DidOperations.Contract.Tests.csproj \
    --configuration Release \
    --no-build \
    --verbosity normal \
    --logger "console;verbosity=detailed"
echo ""

# Summary
echo "=========================================="
echo -e "${GREEN}✓ All tests completed successfully!${NC}"
echo "=========================================="
echo ""
echo "HeroSD-JWT integration is working correctly!"
echo ""
echo "Next steps:"
echo "1. Review any API warnings or suggestions"
echo "2. Test credential issuance with selective disclosure"
echo "3. Test presentation verification with partial disclosures"
echo "4. Update documentation if needed"
echo ""
