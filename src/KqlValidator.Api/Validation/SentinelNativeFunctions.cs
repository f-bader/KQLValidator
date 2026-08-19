namespace KqlValidator.Validation;

internal static class SentinelNativeFunctions
{
    public static IReadOnlyDictionary<string, SchemaFunction> Create() => Functions()
        .ToDictionary(function => function.Name, StringComparer.OrdinalIgnoreCase);

    private static IEnumerable<SchemaFunction> Functions()
    {
        yield return new("_GetWatchlistAlias", [], Columns("WatchlistAlias:string"));
        yield return Watchlist("_GetWatchlist");
        yield return Watchlist("_ASIM_GetWatchlistRaw", new("watchlistAlias", "string"), new("keys", "dynamic", true));
        yield return Watchlist("_ASIM_GetWatchlistsRaw", new("watchlistAliases", "dynamic"), new("keys", "dynamic", true));

        foreach (var name in new[]
        {
            "_ASIM_LookupDnsQueryType", "_ASIM_LookupDnsResponseCode", "_ASIM_LookupICMPType",
            "_ASIM_LookupNetworkProtocol", "_ASIM_LookupHTTPStatusCode", "_ASIM_LookupAADcodes",
        })
            yield return new(name, [new("code", "long")], ScalarReturnType: "string");

        yield return Resolve("_ASIM_ResolveDnsQueryType", "DnsQueryType:int", "DnsQueryTypeName:string");
        yield return Resolve("_ASIM_ResolveDnsResponseCode", "DnsResponseCode:int", "DnsResponseCodeName:string");
        yield return Resolve("_ASIM_ResolveICMPType", "NetworkIcmpCode:int", "NetworkIcmpType:string");
        yield return Resolve("_ASIM_ResolveNetworkProtocol", "NetworkProtocolNumber:int", "NetworkProtocol:string");
        yield return Resolve("_ASIM_ResolveFQDN", "ExtractedHostname:string", "Domain:string", "DomainType:string", "FQDN:string");
        yield return Resolve("_ASIM_ResolveSrcFQDN", "SrcHostname:string", "SrcDomain:string", "SrcDomainType:string", "SrcFQDN:string");
        yield return Resolve("_ASIM_ResolveDstFQDN", "DstHostname:string", "DstDomain:string", "DstDomainType:string", "DstFQDN:string");
        yield return Resolve("_ASIM_ResolveDvcFQDN", "DvcHostname:string", "DvcDomain:string", "DvcDomainType:string", "DvcFQDN:string");

        yield return new("_ASIM_GetUsernameType", [new("username", "string")], ScalarReturnType: "string");
        yield return new("_ASIM_GetWindowsUserType", [new("username", "string"), new("sid", "string")], ScalarReturnType: "string");
        yield return new("_ASIM_GetUserType", [new("username", "string"), new("sid", "string")], ScalarReturnType: "string");
        yield return new("_ASIM_GetDisabledParsers", [new("parser", "string")], ScalarReturnType: "bool");
        yield return new("_ASIM_GetSourceBySourceType", [new("sourceType", "string")], Columns("SourceType:string", "Source:string"));
        yield return new("_ASIM_IdentityInfo", [], Columns("TimeGenerated:datetime", "UserPrincipalName:string", "UserId:string", "UserType:string", "UserSid:string", "UserEmail:string"));
        yield return new("_ASIM_Enrich_IdentityInfo", [new("AadIdField", "string", true), new("TenantIdField", "string", true), new("SidField", "string", true), new("UpnField", "string", true), new("EmailField", "string", true)], Columns("UserPrincipalName:string", "UserId:string", "UserType:string", "UserSid:string", "UserEmail:string"), PreserveInput: true, RequiresTabularInput: true);
    }

    private static SchemaFunction Watchlist(string name, params FunctionParameter[] parameters) =>
        new(name, parameters.Length == 0 ? [new("watchlistAlias", "string")] : parameters,
            Columns("_DTItemId:string", "LastUpdatedTimeUTC:datetime", "SearchKey:string", "WatchlistAlias:string", "WatchlistItem:dynamic",
                "Asset Type:string", "Asset Id:string", "Asset Name:string", "Asset FQDN:string", "IP Address:string",
                "User Identifier:string", "User AAD Object Id:string", "User On-Prem Sid:string", "User Principal Name:string",
                "IP Subnet:string", "Range Name:string", "UserState:string", "Notification date:string", "Termination date:string",
                "Employee Id:string", "Email:string", "Associated Privileged Account ID:string", "Associated Privileged Account:string",
                "Service Identifier:string", "Service AAD Object Id:string", "Service On-Prem Sid:string", "Service Principal Name:string",
                "Owner User Identifier:string", "Owner User AAD Object Id:string", "Owner User On-Prem Sid:string", "Owner User Principal Name:string", "Tags:string"));

    private static SchemaFunction Resolve(string name, params string[] columns) =>
        new(name, [new("fieldName", "string")], Columns(columns), PreserveInput: true, RequiresTabularInput: true);

    private static IReadOnlyList<SchemaColumn> Columns(params string[] values) => values.Select(value =>
    {
        var separator = value.LastIndexOf(':');
        return new SchemaColumn(value[..separator], value[(separator + 1)..]);
    }).ToArray();
}
