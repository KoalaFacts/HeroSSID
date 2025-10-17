# Running HeroSSID with .NET Aspire

This project uses .NET Aspire 9.5.1 for orchestration instead of manual docker-compose management.

## Prerequisites

- .NET 9.0 SDK
- Docker Desktop (for running containers)
- Visual Studio 2022 or VS Code with C# DevKit (optional but recommended)

## Starting the Application

### Option 1: Using dotnet CLI (Recommended)

```bash
# Navigate to the AppHost project
cd src/Services/HeroSSID.AppHost

# Run the Aspire orchestrator
dotnet run
```

This will:
1. Start the Aspire dashboard at `http://localhost:15888` (or similar)
2. Automatically pull and start the PostgreSQL container
3. Automatically pull and start the Hyperledger Indy pool container (Von Network)
4. Configure service discovery between all components
5. Provide health monitoring and logs in the dashboard

### Option 2: Using Visual Studio

1. Open `HeroSSID.sln` in Visual Studio 2022
2. Set `HeroSSID.AppHost` as the startup project
3. Press F5 or click "Start Debugging"
4. The Aspire dashboard will open automatically in your browser

### Option 3: Using VS Code

1. Open the workspace in VS Code
2. Install the C# DevKit extension
3. Open the command palette (Ctrl+Shift+P)
4. Select "Tasks: Run Task" → "Run AppHost"

## Accessing Services

Once Aspire is running, you can access:

| Service | URL | Purpose |
|---------|-----|---------|
| **Aspire Dashboard** | `http://localhost:15888` | Monitor all services, view logs, check health |
| **PostgreSQL** | `localhost:5432` | Database (user: `postgres`, password: auto-generated) |
| **PgAdmin** | `http://localhost:8080` | PostgreSQL web UI |
| **Indy Pool Web UI** | `http://localhost:8000` | Von Network monitoring interface |
| **Indy Nodes** | `localhost:9701-9708` | Indy validator and client nodes |

## Database Connection String

Aspire automatically generates connection strings with service discovery. The CLI and tests will use:

```
ConnectionStrings__herossid-db = (auto-injected by Aspire)
```

You don't need to configure this manually when running via Aspire.

## Applying Database Migrations

### Using Aspire (Automatic - Coming Soon)

The AppHost will be updated to automatically apply migrations on startup.

### Manual Migration

If you need to apply migrations manually:

```bash
# Ensure PostgreSQL is running (via Aspire or docker-compose)
cd src/Libraries/HeroSSID.Data

# Apply migrations
dotnet ef database update --startup-project ../../Services/HeroSSID.AppHost
```

## Extracting Indy Genesis File

The Hyperledger Indy pool requires a genesis transaction file for client connections. To extract it:

```bash
# Get the container name from Aspire dashboard
# Usually it will be something like: indy-pool-<hash>

# Extract genesis file
docker exec <container-name> cat /home/indy/.indy_client/pool/*/pool_transactions_genesis > genesis/pool_transactions_genesis
```

Alternatively, wait for the pool to fully start and download it from:
```
http://localhost:8000/genesis
```

## Stopping Services

### Using dotnet CLI
- Press `Ctrl+C` in the terminal where `dotnet run` is executing
- Aspire will gracefully stop all containers

### Using Visual Studio
- Click "Stop Debugging" or press Shift+F5
- Containers will be stopped automatically

## Troubleshooting

### Containers not starting

Check the Aspire dashboard logs for specific error messages. Common issues:

1. **Port conflicts**: Ensure ports 5432, 8000, 8080, 9701-9708, 15888 are not in use
2. **Docker not running**: Start Docker Desktop
3. **Image pull errors**: Check your internet connection

### PostgreSQL connection errors

- Verify PostgreSQL is running in Aspire dashboard (should show green/healthy)
- Check connection string in Aspire dashboard under "Resources" → "postgres"
- Ensure migrations have been applied

### Indy pool not accessible

- Wait 30-60 seconds after starting (Von Network takes time to initialize)
- Check `http://localhost:8000` - should show Von Network web interface
- Verify all 4 nodes are running in Aspire dashboard

## Advantages Over docker-compose

1. **Integrated Dashboard**: Single pane of glass for logs, metrics, health checks
2. **Service Discovery**: Automatic connection string injection
3. **Development Experience**: F5 in Visual Studio starts everything
4. **Resource Management**: Aspire handles container lifecycle
5. **Health Monitoring**: Built-in health checks and retry logic
6. **Distributed Tracing**: OpenTelemetry integration (when we add it in v2)

## Legacy docker-compose

The `docker-compose.yml` files are still present for reference and can be used if you prefer manual orchestration:

```bash
# Start services manually
docker-compose up -d

# Stop services
docker-compose down
```

However, Aspire is the recommended approach for development.
