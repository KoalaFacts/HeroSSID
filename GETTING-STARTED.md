# Getting Started with HeroSSID MVP

**Welcome!** This guide will get you from zero to running your first DID creation in ~30 minutes.

---

## ✅ Pre-Implementation Checklist

### Step 1: Verify Prerequisites (5 min)

```bash
# Check .NET 9.0 SDK installed
dotnet --version
# Should show: 9.0.x or higher

# Check Docker installed
docker --version
# Should show: Docker version 20.x or higher

# Check Docker Compose installed
docker-compose --version
# Should show: Docker Compose version 2.x or higher

# Check Git installed
git --version
# Should show: git version 2.x or higher
```

**If any missing**:
```bash
# Windows (using winget)
winget install Microsoft.DotNet.SDK.9
winget install Docker.DockerDesktop

# macOS (using brew)
brew install --cask dotnet-sdk
brew install --cask docker

# Linux
# Follow official .NET and Docker installation guides
```

---

### Step 2: Project Setup (10 min)

```bash
# Navigate to project directory
cd /c/projects/BeingCiteable/HeroSSID

# Verify project files exist
ls -la
# Should see: docker-compose.yml, HeroSSID.sln, .gitignore, README.md, specs/

# Start infrastructure
docker-compose up -d

# Wait ~30 seconds for services to be healthy
docker-compose ps
# Both postgres and indy-pool should show "Up (healthy)"

# View logs if needed
docker-compose logs -f
# Ctrl+C to exit
```

**Troubleshooting**:
- If PostgreSQL fails: Check port 5432 not in use (`netstat -an | grep 5432`)
- If Indy pool fails: Check ports 9000, 9701-9708 not in use
- Docker issues: Restart Docker Desktop, then `docker-compose up -d` again

---

### Step 3: Verify Infrastructure (5 min)

```bash
# Test PostgreSQL connection
docker exec herossid-postgres psql -U herossid -d herossid -c "SELECT version();"
# Should show PostgreSQL 17.x version info

# Check Indy pool web UI (optional)
# Open browser: http://localhost:9000
# Should see Von Network web interface with 4 nodes

# Extract genesis file (needed for Indy connection)
mkdir -p genesis
docker exec herossid-indy-pool cat /home/indy/.indy_client/pool/sandbox/sandbox.txn > genesis/pool_transactions_genesis

# Verify genesis file created
cat genesis/pool_transactions_genesis | head -n 5
# Should see JSON with node transaction data
```

---

### Step 4: Initial Build (10 min)

**You'll do this as part of Day 1 tasks, but verify it works now:**

```bash
# Create solution (Task T001)
dotnet new sln -n HeroSSID

# Verify solution created
ls HeroSSID.sln

# Restore any existing packages
dotnet restore

# Build (will fail initially - no projects yet)
dotnet build
# Expected: Error - no projects in solution (this is OK!)
```

**Note**: You'll add projects starting with Task T002 in the implementation phase.

---

## 📚 Read These Documents First (30 min)

### Essential Reading (Must Read)

1. **[specs/001-core-herossid-identity/README.md](specs/001-core-herossid-identity/README.md)** (10 min)
   - MVP overview
   - Quick reference
   - FAQ

2. **[specs/001-core-herossid-identity/tasks.md](specs/001-core-herossid-identity/tasks.md)** (15 min)
   - Your 77-task checklist
   - Organized by week
   - Daily breakdown

3. **[DEPENDENCIES-REVISED.md](specs/001-core-herossid-identity/DEPENDENCIES-REVISED.md)** (5 min)
   - 11 packages (includes .NET Aspire)
   - Local encryption strategy
   - Migration path to Key Vault

### Reference (Read as Needed)

4. **[mvp-architecture-decisions.md](specs/001-core-herossid-identity/mvp-architecture-decisions.md)**
   - 10 ADRs explaining choices
   - Read when questioning a decision

5. **[data-model.md](specs/001-core-herossid-identity/data-model.md)**
   - 4 entities (DID, Schema, CredDef, Credential)
   - Read when implementing entities

6. **[plan.md](specs/001-core-herossid-identity/plan.md)**
   - Technical implementation plan
   - Constitution check
   - Read when stuck on architecture

---

## 🎯 Day 1: First Steps (Tasks T001-T008)

### Morning: Project Structure (T001-T007)

```bash
# Task T001: Create solution (already done above)
dotnet new sln -n HeroSSID

# Task T002: Create directory structure
mkdir -p src/Libraries src/Services src/Shared src/Cli tests/Unit tests/Integration tests/Contract

# Task T003: Create .NET Aspire AppHost project
dotnet new aspire-apphost -n HeroSSID.AppHost -o src/Services/HeroSSID.AppHost
dotnet sln add src/Services/HeroSSID.AppHost

# Task T004: Create CLI project
dotnet new console -n HeroSSID.Cli -o src/Cli/HeroSSID.Cli
dotnet sln add src/Cli/HeroSSID.Cli

# Task T005: Configure .editorconfig
# Create .editorconfig file (see below)

# Task T006: Create Directory.Build.props
# Create Directory.Build.props file (see below)

# Task T007: docker-compose.yml (already created!)
# Already exists - just verify it works
```

### Afternoon: Verify Build & Aspire Dashboard

```bash
# Build solution
dotnet build

# Should succeed now with CLI and AppHost projects
# Output: Build succeeded. 0 Warning(s), 0 Error(s)

# Start Aspire AppHost (includes PostgreSQL connection + CLI)
dotnet run --project src/Services/HeroSSID.AppHost

# Open Aspire Dashboard in browser: http://localhost:15888
# You should see:
# - Resources panel (will show PostgreSQL once configured on Day 3-4)
# - Logs panel (will show CLI output)
# - Traces panel (for future REST API)
# - Metrics panel (service health)

# Or run CLI directly (without Aspire)
dotnet run --project src/Cli/HeroSSID.Cli
```

---

## 📝 Essential Files to Create on Day 1

### .editorconfig (Task T005)

Create `.editorconfig` in repository root:

```ini
root = true

[*]
charset = utf-8
insert_final_newline = true
trim_trailing_whitespace = true

[*.{cs,csx,vb,vbx}]
indent_size = 4
indent_style = space

[*.{json,yml,yaml}]
indent_size = 2
indent_style = space

[*.cs]
# .NET coding conventions
dotnet_sort_system_directives_first = true
dotnet_style_qualification_for_field = false:warning
dotnet_style_qualification_for_property = false:warning
dotnet_style_qualification_for_method = false:warning
dotnet_style_qualification_for_event = false:warning

# Naming conventions
dotnet_naming_rule.interfaces_should_be_prefixed_with_i.severity = warning
dotnet_naming_rule.interfaces_should_be_prefixed_with_i.symbols = interface
dotnet_naming_rule.interfaces_should_be_prefixed_with_i.style = begins_with_i

# Code style rules
csharp_prefer_braces = true:warning
csharp_using_directive_placement = outside_namespace:warning
```

### Directory.Build.props (Task T006)

Create `Directory.Build.props` in repository root:

```xml
<Project>
  <PropertyGroup>
    <TargetFramework>net9.0</TargetFramework>
    <LangVersion>latest</LangVersion>
    <Nullable>enable</Nullable>
    <ImplicitUsings>enable</ImplicitUsings>
    <TreatWarningsAsErrors>true</TreatWarningsAsErrors>
  </PropertyGroup>

  <ItemGroup>
    <!-- Common package versions -->
    <PackageReference Update="Aspire.Hosting.AppHost" Version="9.5.1" />
    <PackageReference Update="Aspire.Hosting.PostgreSQL" Version="9.5.1" />
    <PackageReference Update="Aspire.Npgsql.EntityFrameworkCore.PostgreSQL" Version="9.5.1" />
    <PackageReference Update="Microsoft.Extensions.DependencyInjection" Version="9.0.0" />
    <PackageReference Update="Microsoft.Extensions.Configuration" Version="9.0.0" />
    <PackageReference Update="Microsoft.Extensions.Caching.Memory" Version="9.0.0" />
    <PackageReference Update="Npgsql.EntityFrameworkCore.PostgreSQL" Version="9.0.4" />
    <PackageReference Update="Serilog" Version="4.1.0" />
    <PackageReference Update="Serilog.Sinks.File" Version="6.0.0" />
    <PackageReference Update="Spectre.Console" Version="0.49.1" />
    <PackageReference Update="System.CommandLine" Version="2.0.0-beta4.22272.1" />
    <PackageReference Update="xunit" Version="3.0.0" />
    <PackageReference Update="xunit.runner.visualstudio" Version="3.0.0" />
  </ItemGroup>
</Project>
```

---

## 🚀 Ready to Start Implementation?

### Day 1 Checklist

- [ ] Prerequisites installed (.NET 9, Docker)
- [ ] Docker services running (`docker-compose ps` shows healthy)
- [ ] Genesis file extracted (`genesis/pool_transactions_genesis` exists)
- [ ] Solution created (`HeroSSID.sln` exists)
- [ ] Directory structure created (`src/`, `tests/` exist)
- [ ] Aspire AppHost project created (`src/Services/HeroSSID.AppHost`)
- [ ] CLI project created and builds successfully
- [ ] Aspire Dashboard accessible (http://localhost:15888)
- [ ] `.editorconfig` created
- [ ] `Directory.Build.props` created
- [ ] Read tasks.md (know what's coming)
- [ ] Read DEPENDENCIES-REVISED.md (understand dependency strategy)

**If all checked, you're ready for Day 2!** ✅

---

## 💡 Daily Workflow

### Each Morning
1. Open `specs/001-core-herossid-identity/tasks.md`
2. Find next unchecked task
3. Read task description
4. Ask AI if unclear

### Each Afternoon
1. **Write tests FIRST** (verify they fail ⚠️)
2. **Implement** to make tests pass ✅
3. **Integrate** with CLI if needed
4. **Manual test** the command
5. **Commit**: `git commit -m "[T###] Task description"`

### Each Evening
1. Mark completed tasks in tasks.md
2. Push commits to Git
3. Plan tomorrow's tasks
4. Reflect on progress

---

## 🆘 Getting Help

### Stuck on a Task?
1. Re-read task description carefully
2. Check referenced documents (data-model.md, plan.md)
3. Review ADR for relevant decision (mvp-architecture-decisions.md)
4. **Timebox to 30 minutes** - if still stuck, ask AI for help

### Common Issues

**Problem**: Can't connect to PostgreSQL
**Solution**:
```bash
docker-compose down
docker-compose up -d
# Wait 30 seconds
docker-compose ps  # Check health
```

**Problem**: Can't find Open Wallet Foundation SDK on NuGet
**Solution**:
- Package name may have changed - search nuget.org for "Hyperledger Aries"
- Alternative: Use `Hyperledger.Aries` package directly
- Update Directory.Build.props with correct package name

**Problem**: Tests failing on ledger connection
**Solution**:
- Verify genesis file exists: `cat genesis/pool_transactions_genesis`
- Check Indy pool running: `docker logs herossid-indy-pool`
- Verify appsettings.json has correct GenesisPath

**Problem**: Build errors on new library
**Solution**:
```bash
# Clean and rebuild
dotnet clean
dotnet restore
dotnet build
```

---

## 📊 Tracking Progress

### Weekly Milestones

**End of Week 1**:
- [ ] Can run CLI tool
- [ ] Can connect to PostgreSQL
- [ ] Can connect to Indy ledger
- [ ] Basic logging works

**End of Week 2**:
- [ ] `herossid did create` command works
- [ ] DID appears on Indy ledger
- [ ] DID stored in database

**End of Week 3**:
- [ ] `herossid schema publish` works
- [ ] `herossid credential-definition create` works
- [ ] Both stored on ledger

**End of Week 4**:
- [ ] `herossid credential issue` works
- [ ] `herossid credential verify` works
- [ ] Complete demo script runs successfully

---

## 🎯 Success Definition

**You're successful if on Day 20 you can run**:

```bash
# Demo script
./scripts/demo.sh

# Which runs:
herossid did create --name "Acme University"
herossid schema publish --name "Degree" --version "1.0" --attributes "name,degree,year"
herossid credential-definition create --schema <id> --issuer <did>
herossid credential issue --issuer <did> --holder <holder-did> --cred-def <id> --attributes '{"name":"Alice","degree":"BSc CS","year":"2024"}'
herossid credential verify --file credential.json

# Output: ✅ VALID
```

**If this works, MVP is complete!** 🎉

---

## 📞 Next Steps

1. **Verify** all checkboxes in "Day 1 Checklist" above
2. **Open** `specs/001-core-herossid-identity/tasks.md`
3. **Start** with Task T001 (if not already done)
4. **Work** through tasks sequentially
5. **Commit** after each task completion

**Let's build this!** 🚀

---

*Document created: 2025-10-15*
*For: HeroSSID MVP implementation*
*Timeline: 20 working days*
