var builder = DistributedApplication.CreateBuilder(args);

// Add PostgreSQL database for HeroSSID
var postgres = builder.AddPostgres("postgres")
    .WithPgAdmin()
    .AddDatabase("herossid-db");

// Future: Add CLI project reference here when ready
// var cli = builder.AddProject<Projects.HeroSSID_Cli>("herossid-cli")
//     .WithReference(postgres);

builder.Build().Run();
