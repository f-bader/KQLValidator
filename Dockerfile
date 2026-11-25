# syntax=docker/dockerfile:1.7
FROM mcr.microsoft.com/dotnet/sdk:10.0.404-noble@sha256:8c6edfb26c85153f236d26efebd9ad349aec403583f343f201ee67838b23658d AS build
ARG SOURCE_REVISION=unknown
ARG VERSION=0.0.0-local
ARG ENABLE_STATUS_SITE=true
WORKDIR /src

COPY global.json Directory.Build.props Directory.Packages.props NuGet.config ./
COPY src/KqlValidator.Api/KqlValidator.Api.csproj src/KqlValidator.Api/packages.lock.json src/KqlValidator.Api/
RUN dotnet restore src/KqlValidator.Api/KqlValidator.Api.csproj --locked-mode

COPY src/KqlValidator.Api/ src/KqlValidator.Api/
RUN dotnet publish src/KqlValidator.Api/KqlValidator.Api.csproj \
    --configuration Release \
    --no-restore \
    --output /app/publish \
    /p:UseAppHost=false \
    /p:Version=$VERSION \
    /p:SourceRevisionId=$SOURCE_REVISION \
    /p:EnableStatusSite=$ENABLE_STATUS_SITE

FROM mcr.microsoft.com/dotnet/aspnet:10.0.15-noble-chiseled@sha256:7c625e44e5d588b4d7b2a913e94ca4bd5098ce47442da404829e4c7936a764e1 AS final
ARG SOURCE_REVISION=unknown
ARG VERSION=0.0.0-local
LABEL org.opencontainers.image.title="kql-validator" \
      org.opencontainers.image.description="Unauthenticated, stateless KQL validator for Microsoft Defender XDR and Microsoft Sentinel" \
      org.opencontainers.image.source="https://github.com/f-bader/KQLValidator" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="$VERSION" \
      org.opencontainers.image.revision="$SOURCE_REVISION"
# No HEALTHCHECK on purpose: the chiseled base has no shell or curl; liveness and
# readiness probes are defined in infra/main.bicep against /health/live and /health/ready.
WORKDIR /app
COPY --from=build /app/publish ./

ENV ASPNETCORE_URLS=http://+:8080 \
    DOTNET_EnableDiagnostics=0
EXPOSE 8080
USER $APP_UID
ENTRYPOINT ["dotnet", "KqlValidator.Api.dll"]
