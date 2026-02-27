# Minimal setup samples

These are copy/paste starter files for wiring CodeWorks.Auth in a minimal API.

- `sqlserver/Program.cs` uses `Microsoft.Data.SqlClient`
- `postgresql/Program.cs` uses `Npgsql`
- `mvc-startup/` is a traditional ASP.NET Core Web API sample using `Startup.cs`
- `mvc-startup/mvc-sample.http` is the standard lightweight test suite (VS Code REST client)
- `mvc-startup/CodeWorks.Auth.MvcSample.postman_collection.json` includes auth/account request flow
- `mvc-startup/CodeWorks.Auth.MvcSample.postman_environment.json` provides local variables
- `sqlserver/appsettings.example.json` provides SQL Server + JWT (+ Redis for optional distributed cache)
- `postgresql/appsettings.example.json` provides PostgreSQL + JWT

Notes:
- These are examples only and are excluded from this library build.
- Replace placeholder store and verifier implementations with your real implementations.
- Run the schema scripts before starting:
  - `../sql/sqlserver-auth-stores.sql`
  - `../sql/postgresql-auth-stores.sql`
- Copy `appsettings.example.json` to `appsettings.json` in your app and update values.
