# Testing HeroSD-JWT Integration

## Automated CI Testing (GitHub Actions)

The CI workflow should have been automatically triggered when we pushed the changes. Check the status:

1. Visit: https://github.com/KoalaFacts/HeroSSID/actions
2. Look for the latest workflow run on branch `claude/test-herosd-jwt-package-011CURmfqXF6ged1DUZMsC7W`
3. The workflow will:
   - Restore NuGet packages (including HeroSD-JWT)
   - Build the solution
   - Run all tests

### What to Watch For

**If HeroSD-JWT package is available on NuGet.org:**
- Restore should succeed
- Build may fail if API doesn't match our assumptions
- Check build logs for any type mismatches or missing members

**If HeroSD-JWT package is NOT yet published:**
- Restore will fail with "Unable to find package 'HeroSD-JWT'"
- This is expected if the package hasn't been published to NuGet.org yet

## Local Testing

### Prerequisites
- .NET 9.0 SDK installed
- HeroSD-JWT package published to NuGet.org (or available in a local feed)

### Run the Test Script

```bash
# Make sure you're in the repository root
cd /path/to/HeroSSID

# Run the comprehensive test script
./test-herosd-jwt-integration.sh
```

The script will:
1. ✅ Verify .NET 9.0 SDK is installed
2. ✅ Clean previous builds
3. ✅ Restore NuGet packages (downloads HeroSD-JWT)
4. ✅ Verify HeroSD-JWT installation
5. ✅ Build the solution
6. ✅ Run all unit tests
7. ✅ Run integration tests
8. ✅ Run contract tests

### Manual Testing Steps

If you prefer to test manually:

```bash
# 1. Restore packages
dotnet restore

# 2. Check if HeroSD-JWT was restored
dotnet list src/Libraries/HeroSSID.Credentials/HeroSSID.Credentials.csproj package

# 3. Build
dotnet build --configuration Release

# 4. Run tests
dotnet test --configuration Release --no-build
```

## Expected Outcomes

### Scenario 1: HeroSD-JWT API Matches Our Implementation ✅

**Expected:**
- ✅ All tests pass
- ✅ No build warnings related to HeroSD-JWT
- ✅ SD-JWT generation and verification work correctly

**Action:** Celebrate! The integration is successful.

### Scenario 2: HeroSD-JWT API Differs from Assumptions ⚠️

**Expected:**
- ❌ Build fails with compilation errors
- Errors like: `'SdJwtGenerator' does not contain a definition for 'Generate'`
- Or: `The name 'SdJwtOptions' does not exist in the current context`

**Action:** Adjust the implementation files based on actual HeroSD-JWT API:
- `src/Libraries/HeroSSID.Credentials/Implementations/HeroSdJwtGenerator.cs`
- `src/Libraries/HeroSSID.Credentials/Implementations/HeroSdJwtVerifier.cs`

Check HeroSD-JWT documentation or source code for correct API usage.

### Scenario 3: Package Not Yet Published ❌

**Expected:**
- ❌ Restore fails: `Unable to find package 'HeroSD-JWT'`

**Action:** Either:
1. Wait for HeroSD-JWT to be published to NuGet.org
2. Temporarily revert to mock implementations:
   ```bash
   # Edit ServiceCollectionExtensions.cs
   # Change back to MockSdJwtGenerator and MockSdJwtVerifier
   ```

## Troubleshooting

### Build Errors

If you see compilation errors, check:

1. **Namespace issues**: Ensure `using HeroSDJWT;` is correct
2. **Type names**: Check if `SdJwtGenerator`, `SdJwtVerifier` are correct
3. **Method signatures**: Verify method names and parameters match
4. **Property names**: Check if `CompactSerialization`, `Disclosures`, etc. are correct

### Test Failures

If tests fail:

1. **Check if it's the mock tests**: Mock tests might still be using old implementations
2. **Review test assumptions**: Some tests may make assumptions about mock behavior
3. **Check SD-JWT format**: Ensure format is compatible with existing code

### Package Not Found

If NuGet can't find HeroSD-JWT:

```bash
# Check package sources
dotnet nuget list source

# Try to search for the package
dotnet nuget search HeroSD-JWT

# If using a private feed, add it:
dotnet nuget add source https://your-feed-url -n YourFeedName
```

## Getting Help

If you encounter issues:

1. Check the HeroSD-JWT GitHub repo for documentation
2. Review build/test logs for specific error messages
3. Verify package version compatibility
4. Check if package is correctly published to NuGet.org

## Next Steps After Successful Tests

Once tests pass:

1. ✅ Review performance of SD-JWT operations
2. ✅ Test with real-world credential scenarios
3. ✅ Update documentation with examples
4. ✅ Consider creating integration examples
5. ✅ Merge the integration branch

---

**Created:** 2025-10-24
**Branch:** claude/test-herosd-jwt-package-011CURmfqXF6ged1DUZMsC7W
