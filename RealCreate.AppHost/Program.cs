var builder = DistributedApplication.CreateBuilder(args);

var apiservice = builder.AddProject<Projects.RealCreate_ApiService>("apiservice");

builder.AddProject<Projects.RealCreate_Web>("webfrontend")
    .WithReference(apiservice);

builder.Build().Run();
