# NuGet Packaging

## 1) Build + pack the library project

Always pack the library project directly (not the repo root/solution):

```bash
dotnet pack CodeWorks.Auth.csproj -c Release /p:GeneratePackageOnBuild=false
```

Outputs:

- `bin/Release/CodeWorks.Auth.<version>.nupkg`
- `bin/Release/CodeWorks.Auth.<version>.snupkg`

## 2) Push package(s) to NuGet

```bash
dotnet nuget push bin/Release/CodeWorks.Auth.<version>.nupkg -k <NUGET_API_KEY> -s https://api.nuget.org/v3/index.json
dotnet nuget push bin/Release/CodeWorks.Auth.<version>.snupkg -k <NUGET_API_KEY> -s https://api.nuget.org/v3/index.json
```

## 3) Tag the release in git

```bash
git tag v<version>
git push origin v<version>
```

## One-step VS Code task (recommended)

Use the task:

- `release: bump-tag-push`

It will:

1. Update `<Version>` in `CodeWorks.Auth.csproj`
2. Run release pack validation
3. Commit the version bump
4. Create `v<version>` tag
5. Push branch and tag to `origin`

Task files:

- `.vscode/tasks.json`
- `scripts/release.sh`