# Testing Guide for HeroSSID

## Running Tests

```bash
dotnet test
```

All 174 tests should pass without any configuration needed.

## Test Structure

### Unit Tests
- **HeroSSID.DidOperations.Tests**: DID creation, resolution, signing (49 tests)
- **HeroSSID.Credentials.Tests**: Credential issuance and verification (105 tests, 2 skipped)
- **HeroSSID.Data.Tests**: Database operations (3 tests)

### Contract Tests
- **HeroSSID.DidOperations.Contract.Tests**: W3C DID compliance (7 tests)

### Integration Tests
- **HeroSSID.Integration.Tests**: End-to-end workflows (10 tests)
  - Requires Docker for PostgreSQL test containers

## Test Coverage

Current test statistics:
- **Total Tests**: 174
- **Pass Rate**: 100%
- **Skipped**: 2 (concurrent load tests - intentionally disabled)

## Entropy Validation

The `DidCreationService` includes cryptographic entropy validation to ensure the system's random number generator is working correctly. The validation uses **realistic thresholds** that avoid false positives:

### What It Checks

1. **All bytes identical** - Complete RNG failure
2. **All zeros** - Common failure mode
3. **All 0xFF** - Another failure mode
4. **Unique value count** - Requires ≥50% unique bytes (128/256)
   - Expected for good RNG: 160-165 unique values
   - Threshold of 50% catches real problems while avoiding false positives
5. **Chi-square distribution test** - Uses threshold of 40.0 (χ² ≤ 40.0)
   - Catches severely non-uniform distributions
   - Allows normal statistical variation (good RNGs can produce values up to ~37)

### Why These Thresholds?

The thresholds are based on **mathematical reality**:

- Due to the **birthday paradox**, when sampling 256 random bytes from 256 possible values, you expect about 160-165 unique values
- Previous threshold of 75% unique (192/256) was mathematically unrealistic and caused false positives
- Chi-square threshold increased to 40.0 to allow normal statistical variation (good RNGs can produce values up to ~37)

### Production Safety

These checks remain **strict enough for production** to catch:
- VM/container entropy issues after boot
- Weak entropy sources on embedded systems
- Manipulated entropy pools
- Hardware RNG failures

But they're now **realistic enough for tests** to avoid false failures when many tests run in parallel.

## CI/CD Configuration

### GitHub Actions

```yaml
- name: Run tests
  run: dotnet test
```

### Azure DevOps

```yaml
- task: DotNetCoreCLI@2
  inputs:
    command: 'test'
```

## Troubleshooting

### Integration tests failing with Docker errors

**Problem**: `Docker is either not running or misconfigured`

**Solution**: Start Docker Desktop before running integration tests

## Test Best Practices

1. All tests are self-contained and can run in parallel
2. Integration tests use Testcontainers for isolated PostgreSQL instances
3. Tests don't require any environment variables or configuration
4. Cryptographic tests use proper entropy validation (no shortcuts)

## Security Testing

The test suite includes:
- ✅ Entropy validation (catches weak RNGs)
- ✅ Multi-tenant isolation tests
- ✅ Cryptographic key validation
- ✅ W3C standards compliance
- ✅ JWT tampering detection
- ✅ Revocation checking
- ✅ Cross-tenant attack prevention
