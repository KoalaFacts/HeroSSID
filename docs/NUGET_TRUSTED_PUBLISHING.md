# NuGet Trusted Publishing Setup

This document explains how to set up NuGet Trusted Publishing for the HeroSSID project using GitHub Actions and OIDC authentication.

## What is NuGet Trusted Publishing?

NuGet Trusted Publishing is a secure way to publish packages to NuGet.org without using long-lived API keys. It uses OpenID Connect (OIDC) to authenticate GitHub Actions workflows directly with NuGet.org, exchanging the OIDC token for a **temporary API key valid for 1 hour**.

### Benefits

- **No long-lived API keys to manage**: Temporary keys expire after 1 hour
- **Enhanced security**: Uses short-lived tokens instead of long-lived API keys
- **Automatic token rotation**: Tokens are automatically generated per workflow run
- **Reduced attack surface**: No credentials to leak or steal
- **No GitHub Secrets needed**: Uses OIDC tokens built into GitHub Actions

## Prerequisites

1. **NuGet.org account** with ownership of the package namespace
2. **GitHub repository** with Actions enabled
3. **.NET 9.0 or later** installed locally

## Setup Instructions

### Step 1: Configure Trusted Publishing Policy on NuGet.org

1. **Sign in to NuGet.org**:
   - Go to [NuGet.org](https://www.nuget.org) and sign in

2. **Navigate to Trusted Publishers**:
   - Go to your account settings
   - Click on **"Trusted publishers"** in the left menu
   - Click **"Add"** to create a new trusted publisher

3. **Configure the policy** (case-insensitive):
   - **Repository Owner**: `BeingCiteable` (your GitHub organization/username)
   - **Repository**: `HeroSSID` (repository name)
   - **Workflow File**: `publish-nuget.yml` (filename only, not full path)
   - **Environment** (optional): Leave empty or specify if you use GitHub environments
   - Click **"Create"**

4. **Repeat for each package** (if needed):
   - You may need to create a separate policy for each package ID
   - Or configure with a wildcard pattern if supported

### Step 2: Configure GitHub Repository Secrets

1. **Add NuGet Username Secret**:
   - Go to your GitHub repository
   - Navigate to **Settings → Secrets and variables → Actions → Secrets**
   - Click **"New repository secret"**
   - Name: `NUGET_USERNAME`
   - Value: Your NuGet.org username
   - Click **"Add secret"**

**Note**: Only your NuGet.org username is needed as a secret. No API keys required! The workflow uses OIDC authentication to get temporary API keys automatically.

### Step 3: Configure Package Metadata

Ensure each `.csproj` file has proper NuGet metadata:

```xml
<PropertyGroup>
  <!-- Package Metadata -->
  <PackageId>HeroSSID.Core</PackageId>
  <Authors>BeingCiteable</Authors>
  <Company>BeingCiteable</Company>
  <Description>Core functionality for HeroSSID - W3C DID and Verifiable Credentials implementation</Description>
  <PackageTags>did;verifiable-credentials;w3c;identity;ssi</PackageTags>
  <PackageLicenseExpression>MIT</PackageLicenseExpression>
  <PackageProjectUrl>https://github.com/BeingCiteable/HeroSSID</PackageProjectUrl>
  <RepositoryUrl>https://github.com/BeingCiteable/HeroSSID</RepositoryUrl>
  <RepositoryType>git</RepositoryType>

  <!-- Package Settings -->
  <GeneratePackageOnBuild>false</GeneratePackageOnBuild>
  <PackageReadmeFile>README.md</PackageReadmeFile>
  <IncludeSymbols>true</IncludeSymbols>
  <SymbolPackageFormat>snupkg</SymbolPackageFormat>
</PropertyGroup>

<ItemGroup>
  <None Include="../../../README.md" Pack="true" PackagePath="\" />
</ItemGroup>
```

### Step 3: How the Workflow Works

The workflow at [.github/workflows/publish-nuget.yml](.github/workflows/publish-nuget.yml) uses NuGet Trusted Publishing:

1. **GitHub Actions generates OIDC token** with `id-token: write` permission
2. **NuGet/login@v1 action** exchanges the OIDC token for a temporary API key (valid 1 hour)
3. **dotnet nuget push** uses the temporary API key to publish packages
4. **Temporary key expires** automatically after 1 hour

#### Key Workflow Steps

```yaml
permissions:
  id-token: write  # Required for OIDC authentication with NuGet.org
  contents: read

- name: NuGet login (OIDC → temporary API key)
  uses: NuGet/login@v1
  id: nuget-login
  with:
    user: ${{ secrets.NUGET_USERNAME }}

- name: Publish to NuGet.org using Trusted Publishing
  run: |
    dotnet nuget push "./packages/*.nupkg" \
      --source https://api.nuget.org/v3/index.json \
      --api-key ${{ steps.nuget-login.outputs.NUGET_API_KEY }} \
      --skip-duplicate
```

### Step 4: Trigger Publishing

**Option 1: Create a GitHub Release** (Recommended)
```bash
# Tag the release
git tag -a v1.0.0 -m "Release v1.0.0"
git push origin v1.0.0

# Create release on GitHub
gh release create v1.0.0 --title "v1.0.0" --notes "Release notes here"
```

The workflow automatically triggers on release publication and uses the tag version.

**Option 2: Manual Workflow Dispatch**
1. Go to **Actions** tab in GitHub
2. Select **"Publish NuGet Packages"** workflow
3. Click **"Run workflow"**
4. Enter the version (e.g., `1.0.0`)
5. Click **"Run workflow"**

### Step 5: Verify Publication

After the workflow completes:

1. **Check workflow status**:
   - Go to the **Actions** tab in GitHub
   - View the workflow run logs
   - Verify all steps completed successfully

2. **Verify packages on NuGet.org**:
   - [HeroSSID.Core](https://www.nuget.org/packages/HeroSSID.Core)
   - [HeroSSID.DidOperations](https://www.nuget.org/packages/HeroSSID.DidOperations)
   - [HeroSSID.Credentials](https://www.nuget.org/packages/HeroSSID.Credentials)
   - [HeroSSID.Data](https://www.nuget.org/packages/HeroSSID.Data)
   - [HeroSSID.Observability](https://www.nuget.org/packages/HeroSSID.Observability)

3. **Check package details**:
   - Version number matches the release
   - Package metadata is correct
   - Symbol packages (.snupkg) are published

## Publishing Locally (For Testing)

To test package creation locally before publishing:

```bash
# Build and pack all packages
dotnet pack --configuration Release --output ./packages

# Test publishing to local feed (optional)
dotnet nuget push "./packages/*.nupkg" --source local-feed
```

**Note**: Local publishing to NuGet.org requires an API key. Trusted Publishing only works from GitHub Actions with the configured workflow.

## Package Versioning Strategy

### Semantic Versioning (SemVer)

Use [Semantic Versioning](https://semver.org/): `MAJOR.MINOR.PATCH[-SUFFIX]`

- **MAJOR**: Breaking changes
- **MINOR**: New features (backward compatible)
- **PATCH**: Bug fixes (backward compatible)
- **SUFFIX**: Pre-release identifier (e.g., `-alpha`, `-beta`, `-rc1`)

### Examples

- `1.0.0` - First stable release
- `1.1.0` - New feature added
- `1.1.1` - Bug fix
- `2.0.0` - Breaking change
- `1.2.0-beta1` - Beta pre-release

## Troubleshooting

### Build Failures

**Issue**: Build fails with NuGet vulnerability check timeouts
```
error NU1900: Warning As Error: Error occurred while getting package vulnerability data
```

**Solution**: Temporarily disable vulnerability checks in CI:
```bash
dotnet build --configuration Release /p:NuGetAudit=false
```

### Publishing Failures

**Issue**: `403 Forbidden` when publishing with Trusted Publishing

**Possible Causes**:
1. **Trusted Publisher not configured** on NuGet.org
   - Go to NuGet.org → Account → Trusted publishers
   - Verify policy exists for your repository

2. **Workflow file name mismatch**
   - Policy must specify: `publish-nuget.yml` (exact filename)
   - Case-insensitive but must match exactly

3. **Repository owner/name mismatch**
   - Verify: Repository Owner = `BeingCiteable`
   - Verify: Repository = `HeroSSID`

4. **Package ownership**
   - Ensure your NuGet.org account owns the package namespace
   - For new packages, you need to own the package ID prefix

5. **NUGET_USERNAME secret not set**
   - Go to GitHub repo → Settings → Secrets and variables → Actions → Secrets
   - Verify `NUGET_USERNAME` secret exists and matches your NuGet.org username

**Issue**: `401 Unauthorized` when using NuGet/login action

**Solution**:
1. Verify `NUGET_USERNAME` secret is set correctly in GitHub
2. Check that Trusted Publisher policy is active on NuGet.org
3. Ensure `permissions: id-token: write` is in the workflow
4. Verify the username exactly matches your NuGet.org account (case-sensitive)

**Issue**: Package already exists with same version

**Solution**:
- Increment the version number
- NuGet.org doesn't allow overwriting existing versions
- Use `--skip-duplicate` flag (already in workflow) to skip existing versions

### Version Conflicts

**Issue**: Local version doesn't match published version

**Solution**:
1. Clear NuGet caches: `dotnet nuget locals all --clear`
2. Restore packages: `dotnet restore --force`

## Security Best Practices

1. ✅ **Use Trusted Publishing**: No long-lived API keys needed
2. ✅ **Enable 2FA** on your NuGet.org account
3. ✅ **Monitor package downloads** for suspicious activity
4. ✅ **Review workflow permissions**: Only grant necessary permissions
5. ✅ **Use symbol packages**: Enables debugging (already configured)
6. ✅ **Sign packages** (optional but recommended for production)
7. ✅ **Protect main branch**: Require PR reviews before merging
8. ✅ **Audit dependencies**: Regularly update NuGet packages

## Quick Start Checklist

Use this checklist to set up NuGet Trusted Publishing:

- [ ] **NuGet.org Setup**
  - [ ] Sign in to [NuGet.org](https://www.nuget.org)
  - [ ] Navigate to Account → Trusted publishers
  - [ ] Add trusted publisher:
    - Repository Owner: `BeingCiteable`
    - Repository: `HeroSSID`
    - Workflow File: `publish-nuget.yml`

- [ ] **GitHub Setup**
  - [ ] Go to repository Settings → Secrets and variables → Actions → Secrets
  - [ ] Add secret `NUGET_USERNAME` with your NuGet.org username

- [ ] **Test the Setup**
  - [ ] Create a test release or run workflow manually
  - [ ] Verify packages appear on NuGet.org
  - [ ] Install packages in a test project

- [ ] **Production Checklist**
  - [ ] Enable 2FA on NuGet.org account
  - [ ] Protect main branch with PR reviews
  - [ ] Set up branch protection rules
  - [ ] Document versioning strategy for team

## References

- [NuGet Trusted Publishing (Official Docs)](https://learn.microsoft.com/en-us/nuget/nuget-org/trusted-publishing)
- [NuGet.org Trusted Publishers](https://www.nuget.org/account/trusted-publishers)
- [GitHub Actions - Publishing packages](https://docs.github.com/en/actions/use-cases-and-examples/publishing-packages/publishing-packages-with-github-actions)
- [Semantic Versioning](https://semver.org/)
- [NuGet Package Metadata](https://learn.microsoft.com/en-us/nuget/create-packages/package-authoring-best-practices)
- [NuGet/login Action](https://github.com/marketplace/actions/nuget-login)
