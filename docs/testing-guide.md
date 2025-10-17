# HeroSSID Testing Guide

This guide explains the testing infrastructure and how to run tests for HeroSSID.

## Test Organization

The project follows a three-tier testing strategy:

### 1. **Unit Tests** (`tests/Unit/`)
- Test individual services and components in isolation
- Use mocks for external dependencies
- Fast execution (<1 second per test)
- Run during development

**Location**: `tests/Unit/HeroSSID.Unit.Tests/`

### 2. **Integration Tests** (`tests/Integration/`)
- Test database operations with real PostgreSQL
- Test end-to-end flows across multiple services
- Use Testcontainers for isolated database
- Medium execution time (~5-10 seconds per test)

**Location**: `tests/Integration/HeroSSID.Integration.Tests/`

### 3. **Contract Tests** (`tests/Contract/`)
- Test interactions with Hyperledger Indy ledger
- Verify W3C DID Core and VC Data Model compliance
- Require local Indy pool running
- Slow execution (~30+ seconds per test)

**Location**: `tests/Contract/` (will be created in Phase 2+)

---

## Prerequisites

### For Unit Tests
- .NET 9.0 SDK
- No external dependencies

### For Integration Tests
- .NET 9.0 SDK
- Docker Desktop (for Testcontainers)
- Internet connection (to pull PostgreSQL image)

### For Contract Tests
- .NET 9.0 SDK
- Docker Desktop
- Local Indy pool running (see [Indy Pool Setup](#indy-pool-setup))

---

## Running Tests

### Run All Tests
```bash
dotnet test
```

### Run Only Unit Tests
```bash
dotnet test --filter "FullyQualifiedName~HeroSSID.Unit.Tests"
```

### Run Only Integration Tests
```bash
dotnet test --filter "FullyQualifiedName~HeroSSID.Integration.Tests"
```

### Run Only Contract Tests
```bash
dotnet test --filter "FullyQualifiedName~HeroSSID.Contract.Tests"
```

### Run with Code Coverage
```bash
dotnet test /p:CollectCoverage=true /p:CoverletOutputFormat=opencover
```

---

## Test Infrastructure Components

### DatabaseFixture

**Location**: `tests/Integration/HeroSSID.Integration.Tests/TestInfrastructure/DatabaseFixture.cs`

**Purpose**: Provides a disposable PostgreSQL container for integration tests

**Usage**:
```csharp
public class MyIntegrationTest : IClassFixture<DatabaseFixture>
{
    private readonly DatabaseFixture _fixture;

    public MyIntegrationTest(DatabaseFixture fixture)
    {
        _fixture = fixture;
    }

    [Fact]
    public async Task TestDatabaseOperation()
    {
        // Arrange
        var dbContext = _fixture.CreateDbContext<HeroDbContext>();

        // Act
        // ... perform database operations

        // Assert
        // ... verify results
    }
}
```

**Features**:
- Automatically starts PostgreSQL 17 container
- Creates isolated database for each test class
- Cleans up after tests complete
- Connection string available via `ConnectionString` property

### MockEncryptionService

**Location**: `tests/Unit/HeroSSID.Unit.Tests/Mocks/MockEncryptionService.cs`

**Purpose**: In-memory encryption mock for unit testing

**Usage**:
```csharp
[Fact]
public async Task TestEncryptionRoundTrip()
{
    // Arrange
    var mockEncryption = new MockEncryptionService();
    var originalData = new byte[] { 0x01, 0x02, 0x03 };

    // Act
    var isValid = await mockEncryption.VerifyRoundTripAsync(originalData);

    // Assert
    Assert.True(isValid);
}
```

**Features**:
- Deterministic XOR encryption (NOT secure - testing only)
- Fast in-memory operations
- Round-trip verification method

---

## Indy Pool Setup

Contract tests require a running Hyperledger Indy pool.

### Start Indy Pool

```bash
cd tests/docker/indy-pool
docker-compose up -d

# Wait for health check (~60 seconds)
docker-compose ps

# View web interface
# Open browser: http://localhost:9000
```

### Extract Genesis File

The genesis file is required for connecting to the Indy pool:

```bash
# From repository root
mkdir -p genesis
docker exec herossid-indy-pool cat /home/indy/.indy_client/pool/sandbox/sandbox.txn > genesis/pool_transactions_genesis

# Verify
cat genesis/pool_transactions_genesis | head -n 5
```

### Stop Indy Pool

```bash
cd tests/docker/indy-pool

# Stop but keep data
docker-compose stop

# Stop and remove data
docker-compose down -v
```

---

## Test Naming Conventions

### Unit Tests
```csharp
// Format: MethodName_Scenario_ExpectedBehavior
[Fact]
public void CreateDid_WithValidInput_ReturnsDid()
{
    // ...
}
```

### Integration Tests
```csharp
// Format: Feature_Scenario_ExpectedOutcome
[Fact]
public async Task DidLifecycle_CreateAndRetrieve_Success()
{
    // ...
}
```

### Contract Tests
```csharp
// Format: LedgerOperation_Scenario_ComplianceCheck
[Fact]
public async Task SchemaPublishing_ValidSchema_W3CCompliant()
{
    // ...
}
```

---

## TDD Workflow (Red-Green-Refactor)

HeroSSID follows strict Test-Driven Development:

### 1. **RED**: Write failing test
```csharp
[Fact]
public void CreateSchema_WithValidInput_ReturnsSchemaId()
{
    // Arrange
    var service = new SchemaDefinitionService();

    // Act
    var schemaId = service.CreateSchema("TestSchema", "1.0", new[] { "name", "age" });

    // Assert
    Assert.NotNull(schemaId);
}
```

**Verify test fails**: `dotnet test` should show RED ❌

### 2. **GREEN**: Implement minimum code to pass
```csharp
public class SchemaDefinitionService
{
    public string CreateSchema(string name, string version, string[] attributes)
    {
        return Guid.NewGuid().ToString(); // Minimal implementation
    }
}
```

**Verify test passes**: `dotnet test` should show GREEN ✅

### 3. **REFACTOR**: Improve code quality
```csharp
public class SchemaDefinitionService
{
    private readonly ILedgerSchemaService _ledgerService;

    public SchemaDefinitionService(ILedgerSchemaService ledgerService)
    {
        _ledgerService = ledgerService;
    }

    public async Task<string> CreateSchemaAsync(string name, string version, string[] attributes)
    {
        ValidateInput(name, version, attributes);
        return await _ledgerService.PublishSchemaAsync(name, version, attributes);
    }

    private static void ValidateInput(string name, string version, string[] attributes)
    {
        if (string.IsNullOrWhiteSpace(name))
            throw new ArgumentException("Schema name is required", nameof(name));

        if (string.IsNullOrWhiteSpace(version))
            throw new ArgumentException("Schema version is required", nameof(version));

        if (attributes == null || attributes.Length == 0)
            throw new ArgumentException("At least one attribute is required", nameof(attributes));
    }
}
```

**Verify tests still pass**: `dotnet test` should remain GREEN ✅

---

## Troubleshooting

### Unit Tests Fail

**Issue**: Tests fail with "Cannot resolve dependency"
**Solution**: Ensure all mocks are properly registered:
```csharp
var mockService = new MockEncryptionService();
var sut = new MyService(mockService);
```

### Integration Tests Hang

**Issue**: Tests hang during database setup
**Solution**:
- Verify Docker is running: `docker ps`
- Check disk space: Testcontainers need ~500MB
- View container logs: `docker logs <container-id>`

### Contract Tests Fail

**Issue**: Tests fail with "Connection refused"
**Solution**:
- Verify Indy pool is running: `docker-compose ps`
- Check health: `curl http://localhost:9000`
- Verify genesis file exists: `ls genesis/pool_transactions_genesis`

### Tests Pass Locally but Fail in CI

**Issue**: Tests pass on dev machine but fail in CI/CD
**Solution**:
- Ensure CI has Docker installed
- Increase timeout for Testcontainers startup (60s+)
- Check network connectivity for image pulls

---

## Best Practices

### 1. **Isolation**
- Each test should be independent
- Use `IClassFixture<DatabaseFixture>` for shared setup
- Clean up test data in `Dispose()` methods

### 2. **Naming**
- Use descriptive test names
- Follow AAA pattern (Arrange-Act-Assert)
- One assertion per test (when possible)

### 3. **Performance**
- Keep unit tests fast (<1s)
- Use `[Trait("Category", "Slow")]` for long tests
- Run slow tests separately: `dotnet test --filter "Category!=Slow"`

### 4. **Data**
- Use test-specific data (not production data)
- Avoid hardcoded values (use constants)
- Use test builders for complex objects

### 5. **Coverage**
- Aim for >80% code coverage
- Focus on business logic, not boilerplate
- Use `dotnet test /p:CollectCoverage=true`

---

## CI/CD Integration

### GitHub Actions Example

```yaml
name: Run Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    services:
      docker:
        image: docker:latest
        options: --privileged

    steps:
      - uses: actions/checkout@v3

      - name: Setup .NET 9.0
        uses: actions/setup-dotnet@v3
        with:
          dotnet-version: '9.0.x'

      - name: Restore dependencies
        run: dotnet restore

      - name: Run unit tests
        run: dotnet test --filter "FullyQualifiedName~Unit.Tests" --no-restore

      - name: Run integration tests
        run: dotnet test --filter "FullyQualifiedName~Integration.Tests" --no-restore

      - name: Start Indy pool
        run: |
          cd tests/docker/indy-pool
          docker-compose up -d
          sleep 60

      - name: Run contract tests
        run: dotnet test --filter "FullyQualifiedName~Contract.Tests" --no-restore

      - name: Collect coverage
        run: dotnet test /p:CollectCoverage=true /p:CoverletOutputFormat=opencover

      - name: Upload coverage
        uses: codecov/codecov-action@v3
        with:
          files: ./coverage.opencover.xml
```

---

## Additional Resources

- [xUnit Documentation](https://xunit.net/)
- [Testcontainers Documentation](https://dotnet.testcontainers.org/)
- [Von Network (Indy Pool)](https://github.com/bcgov/von-network)
- [Open Wallet Foundation SDK](https://github.com/openwallet-foundation/wallet-framework-dotnet)
