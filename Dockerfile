# syntax=docker/dockerfile:1.7
FROM mcr.microsoft.com/dotnet/sdk:10.0.403-noble@sha256:de4fe90a98845d75910b9769662465c84de1a934665c431279d1382b2bddc02b AS build
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

FROM mcr.microsoft.com/dotnet/aspnet:10.0.13-noble-chiseled@sha256:84def277556c2843a44fdeefbd3145d0a2e32d8f736d0c1a7b0a96b2880b0187 AS final
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
