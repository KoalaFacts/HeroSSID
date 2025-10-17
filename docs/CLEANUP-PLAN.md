# HeroSSID Cleanup Plan - Remove Deprecated Indy Components

## Date: 2025-10-17

## Objective
Remove all Hyperledger Indy-specific code and dependencies that are not compatible with the new W3C/OpenWallet direction.

---

## Files/Projects to DELETE

### 1. **HeroSSID.LedgerClient** (ENTIRE PROJECT) ❌
**Path**: `src/Shared/HeroSSID.LedgerClient/`

**Reason**: This entire project is Hyperledger Indy-specific
- `LedgerDIDService.cs` - Indy ledger interactions
- `AgentProvisioningService.cs` - Indy agent setup
- `WalletManagementService.cs` - Indy wallet management
- All interfaces are Indy-specific

**Impact**:
- Remove from solution file
- Remove references from other projects
- Remove from AppHost configuration

**Replacement**: Will create new services for did:web and did:key (no ledger needed)

---

### 2. **Docker Indy Infrastructure** ❌
**Files**:
- Docker-compose Indy pool configuration
- Von Network references
- Indy genesis files

**Reason**: No longer need Indy ledger for did:web/did:key

**Keep**: PostgreSQL configuration (still needed)

---

### 3. **Indy-specific Configuration** ❌
**Files**:
- `appsettings.json` - Remove Indy pool configuration
- `.specify/research/indy-research.md` (if exists)
- Any Indy SDK documentation

---

### 4. **Test Projects for Removed Components** ❌
**Check**:
- Any tests specifically for `LedgerClient`
- Indy-specific integration tests

---

## Files/Code to MODIFY

### 1. **HeroSSID.DidOperations/Services/DidCreationService.cs**

**Current Issues**:
- Uses `did:indy:sovrin:` format
- Simulated Ed25519 keys
- Custom Base58 encoding

**Keep**:
- Overall structure
- Database interaction
- Encryption flow
- Logging patterns

**Modify**:
- Mark as `DidIndyService` (for backward compatibility)
- Add `[Obsolete]` attribute
- Update to use real Ed25519 (next phase)

---

### 2. **HeroSSID.Core/Interfaces**

**Keep**:
- `IKeyEncryptionService` ✅
- All core domain interfaces ✅

**Remove**:
- Any Indy-specific interfaces

---

### 3. **HeroSSID.Data/Entities**

**Keep ALL** ✅:
- `DidEntity` - method-agnostic
- `CredentialSchemaEntity` - will work with W3C VCs
- `CredentialDefinitionEntity` - will adapt to W3C
- `VerifiableCredentialEntity` - already W3C-compatible name

**No changes needed** - database schema is already compatible!

---

### 4. **HeroSSID.AppHost**

**Remove**:
- Indy pool configuration
- Von Network container setup

**Keep**:
- PostgreSQL configuration
- PgAdmin configuration

---

### 5. **Solution File (HeroSSID.sln)**

**Remove**:
- HeroSSID.LedgerClient project reference

---

## Dependencies to REMOVE

### From All Projects:

Check for and remove any Indy-specific NuGet packages:
- `Hyperledger.Indy.*`
- `OpenWallet.Indy.*`
- Any Indy SDK wrappers

### Verify in:
- Directory.Build.props
- Individual .csproj files

---

## Cleanup Steps (Ordered)

### Step 1: Remove Project References
1. Remove `HeroSSID.LedgerClient` from solution
2. Remove project references from dependent projects
3. Remove from AppHost

### Step 2: Delete LedgerClient Project
```bash
rm -rf src/Shared/HeroSSID.LedgerClient/
```

### Step 3: Clean Docker Configuration
1. Remove Indy pool from docker-compose.yml
2. Remove Von Network references
3. Keep only PostgreSQL

### Step 4: Update AppHost
1. Remove Indy container configuration
2. Remove ledger-related environment variables
3. Keep PostgreSQL configuration

### Step 5: Update Configuration Files
1. Remove Indy section from appsettings.json
2. Remove genesis file paths
3. Remove pool configuration

### Step 6: Rename/Mark DidCreationService
1. Rename to `DidIndyService` (backward compat)
2. Add `[Obsolete]` attribute
3. Keep functional for migration period

### Step 7: Clean Build
```bash
dotnet clean
rm -rf */bin */obj */*/bin */*/obj */*/*/bin */*/*/obj
dotnet restore
dotnet build
```

### Step 8: Update Documentation
1. Remove Indy references from README
2. Update RUNNING-WITH-ASPIRE.md
3. Update architecture docs

---

## What to KEEP (Important!)

### ✅ Keep These Projects:
- `HeroSSID.Core` - Core interfaces and models
- `HeroSSID.Data` - Database entities (method-agnostic)
- `HeroSSID.DidOperations` - Rename service, but keep project
- `HeroSSID.Observability` - Logging infrastructure
- `HeroSSID.Cli` - CLI interface
- `HeroSSID.Contracts` - DTOs
- `HeroSSID.AppHost` - Service orchestration (minus Indy)

### ✅ Keep These Files:
- All database entities
- All migrations
- `IKeyEncryptionService` interface
- Logging configuration
- CLI command structure
- Test infrastructure

### ✅ Keep Infrastructure:
- PostgreSQL
- PgAdmin
- .NET Aspire orchestration

---

## Verification Checklist

After cleanup:

- [ ] Solution builds successfully
- [ ] No Indy package references remain
- [ ] PostgreSQL still works
- [ ] Tests still compile (may need updates)
- [ ] No broken project references
- [ ] AppHost starts without Indy components
- [ ] Database migrations still work

---

## Risk Assessment

### LOW RISK ✅
- Removing HeroSSID.LedgerClient (nothing depends on it yet in MVP)
- Removing Indy docker containers
- Updating configuration files

### MEDIUM RISK ⚠️
- Tests may reference removed components
- May need to update some imports

### MITIGATION
- Keep git history
- Can restore files if needed
- Phase 2 DID code stays (just gets renamed)

---

## Expected Outcome

### Before Cleanup:
```
src/
├── Shared/
│   ├── HeroSSID.LedgerClient/     ❌ DELETE
│   └── HeroSSID.Contracts/         ✅ KEEP
├── Libraries/
│   ├── HeroSSID.Core/              ✅ KEEP
│   ├── HeroSSID.Data/              ✅ KEEP
│   └── HeroSSID.DidOperations/     ✅ KEEP (rename service)
```

### After Cleanup:
```
src/
├── Shared/
│   └── HeroSSID.Contracts/         ✅ CLEAN
├── Libraries/
│   ├── HeroSSID.Core/              ✅ READY FOR W3C
│   ├── HeroSSID.Data/              ✅ METHOD-AGNOSTIC
│   └── HeroSSID.DidOperations/     ✅ READY FOR NEW SERVICES
```

---

## Next Steps After Cleanup

1. Add SimpleBase NuGet package
2. Implement real Ed25519
3. Create `DidWebService`
4. Create `DidKeyService`
5. Create `DidServiceFactory`

---

**Status**: 📋 PLAN READY - AWAITING EXECUTION

**Estimated Time**: 1-2 hours

**Risk Level**: LOW ✅
