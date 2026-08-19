# syntax=docker/dockerfile:1.7
FROM mcr.microsoft.com/dotnet/sdk:10.0.302-alpine3.23@sha256:d8ee39817ca03a3757288e83c37ed73cc969a286c603b827c7cbe33add1c2d1c AS build
ARG SOURCE_REVISION=unknown
ARG ENABLE_STATUS_SITE=true
WORKDIR /src

COPY global.json Directory.Build.props ./
COPY src/KqlValidator.Api/KqlValidator.Api.csproj src/KqlValidator.Api/packages.lock.json src/KqlValidator.Api/
RUN dotnet restore src/KqlValidator.Api/KqlValidator.Api.csproj --locked-mode

COPY src/KqlValidator.Api/ src/KqlValidator.Api/
RUN dotnet publish src/KqlValidator.Api/KqlValidator.Api.csproj \
    --configuration Release \
    --no-restore \
    --output /app/publish \
    /p:UseAppHost=false \
    /p:SourceRevisionId=$SOURCE_REVISION \
    /p:EnableStatusSite=$ENABLE_STATUS_SITE

FROM mcr.microsoft.com/dotnet/aspnet:10.0.11-alpine3.23@sha256:4d5339ac9814f1a033a09e664bcf159e9fb386c89b6e7917b3dca7254e656027 AS final
WORKDIR /app
COPY --from=build /app/publish ./

ENV ASPNETCORE_URLS=http://+:8080 \
    DOTNET_EnableDiagnostics=0
EXPOSE 8080
USER $APP_UID
ENTRYPOINT ["dotnet", "KqlValidator.Api.dll"]
