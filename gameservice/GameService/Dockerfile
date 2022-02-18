#See https://aka.ms/containerfastmode to understand how Visual Studio uses this Dockerfile to build your images for faster debugging.

FROM mcr.microsoft.com/dotnet/aspnet:5.0 AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443

FROM mcr.microsoft.com/dotnet/sdk:5.0 AS build
WORKDIR /src
COPY ["GameService/GameService.csproj", "GameService/"]
COPY ["Microsoft.XboxSecureTokens/Microsoft.XboxSecureTokens.csproj", "Microsoft.XboxSecureTokens/"]
RUN dotnet restore "GameService/GameService.csproj"
COPY . .
WORKDIR "/src/GameService"
RUN dotnet build "GameService.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "GameService.csproj" -c Release -o /app/publish
COPY ./certs/RP_Full_Cert.pfx /app/publish/RP_Full_Cert.pfx
COPY ./certs/RP_Cert.cer /app/publish/RP_Cert.cer


FROM base AS final

WORKDIR /app
COPY --from=publish /app/publish .


ENTRYPOINT ["dotnet", "GameService.dll"]