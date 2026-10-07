# syntax=docker/dockerfile:1.7
FROM mcr.microsoft.com/dotnet/sdk:10.0.401-noble@sha256:e70cdb7f80b0348f5cb85f19a8f670fca061f033d57eed12fa003d58b0e06317 AS build
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

FROM mcr.microsoft.com/dotnet/aspnet:10.0.12-noble-chiseled@sha256:9651fa59abcdf177c30392cb44a820605ca5d618429ab37acbf6e7c644510b02 AS final
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
