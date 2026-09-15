# syntax=docker/dockerfile:1

# --- Build ---
FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build
WORKDIR /src

COPY . .
RUN dotnet publish "SnmpSimulator.csproj" -c Release -o /app/publish

# --- Runtime ---
FROM mcr.microsoft.com/dotnet/runtime:9.0 AS runtime
WORKDIR /app

COPY --from=build /app/publish .

# --file/--address/--port/--community are supplied by docker-compose.snmp.yml's
# `command:` for each simulated device; see SnmpSimulator/README.md.
ENTRYPOINT ["dotnet", "SnmpSimulator.dll"]
