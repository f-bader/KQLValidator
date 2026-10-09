using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using KqlValidator.Contracts;
using Kusto.Language.Symbols;

namespace KqlValidator.Validation;

public sealed class SchemaCatalog
{
    private readonly IReadOnlyDictionary<KqlEnvironment, EnvironmentSchema> schemas;
    public ColumnRelationCatalog Relations { get; }

    public SchemaCatalog(string? schemasDirectory = null, string? overlayPath = null)
    {
        var schemaDirectory = schemasDirectory ?? Path.Combine(AppContext.BaseDirectory, "Schemas");
        Relations = new ColumnRelationCatalog(Path.Combine(schemaDirectory, "column-relations.json"), required: schemasDirectory is null);
        var xdr = BuildXdr(schemaDirectory);
        var sentinel = BuildSentinel(schemaDirectory);
        if (!string.IsNullOrWhiteSpace(overlayPath))
        {
            var overlay = CustomSchemaOverlay.Load(overlayPath);
            xdr = Apply(xdr, overlay.Common);
            sentinel = Apply(sentinel, overlay.Common);
            xdr = Apply(xdr, overlay.Environments.GetValueOrDefault(KqlEnvironment.Xdr));
            sentinel = Apply(sentinel, overlay.Environments.GetValueOrDefault(KqlEnvironment.Sentinel));
            var unified = Merge(xdr, sentinel);
            unified = Apply(unified, overlay.Environments.GetValueOrDefault(KqlEnvironment.Unified));
            schemas = new Dictionary<KqlEnvironment, EnvironmentSchema>
            {
                [KqlEnvironment.Xdr] = xdr,
                [KqlEnvironment.Sentinel] = sentinel,
                [KqlEnvironment.Unified] = unified,
            };
        }
        else
        {
            schemas = new Dictionary<KqlEnvironment, EnvironmentSchema>
            {
                [KqlEnvironment.Xdr] = xdr,
                [KqlEnvironment.Sentinel] = sentinel,
                [KqlEnvironment.Unified] = Merge(xdr, sentinel),
            };
        }
        ActionTypes = LoadActionTypes(schemaDirectory);
    }

    public IReadOnlySet<string> ActionTypes { get; }

    public EnvironmentSchema Get(KqlEnvironment environment) => schemas[environment];

    public IReadOnlyList<EnvironmentSummary> List() => schemas
        .Select(pair => new EnvironmentSummary(
            pair.Key.ToString().ToLowerInvariant(),
            pair.Value.Version,
            pair.Value.Tables.Count,
            pair.Value.Functions.Count,
            // Every lint profile applies to every environment today; the field exists so
            // clients can discover valid profile values without hardcoding them.
            Enum.GetValues<LintProfile>()
                .Select(x => x.ToString().ToLowerInvariant()).ToArray()))
        .ToArray();

    private static EnvironmentSchema BuildXdr(string schemaDirectory)
    {
        var tables = LoadSchemaSnapshot("xdr.json", schemaDirectory);
        foreach (var table in LoadSchemaSnapshot("xdr-official-tables.json", schemaDirectory).Values)
            tables[table.Name] = table;
        foreach (var table in new[]
        {
            Table("DeviceEvents", CommonDevice("ActionType:string", "AdditionalFields:dynamic")),
            Table("DeviceProcessEvents", CommonDevice("FileName:string", "FolderPath:string", "SHA1:string", "SHA256:string", "MD5:string", "ProcessCommandLine:string", "ProcessId:long", "ProcessCreationTime:datetime", "ProcessUniqueId:string", "InitiatingProcessFileName:string", "InitiatingProcessCommandLine:string", "InitiatingProcessId:long", "InitiatingProcessCreationTime:datetime", "InitiatingProcessUniqueId:string", "AccountName:string", "AccountDomain:string", "AccountSid:string")),
            Table("DeviceFileEvents", CommonDevice("ActionType:string", "FileName:string", "FolderPath:string", "SHA1:string", "SHA256:string", "MD5:string", "FileSize:long", "InitiatingProcessFileName:string", "InitiatingProcessCommandLine:string", "InitiatingProcessId:long", "InitiatingProcessCreationTime:datetime", "RequestProtocol:string", "RequestSourceIP:string", "AdditionalFields:dynamic")),
            Table("DeviceNetworkEvents", CommonDevice("ActionType:string", "RemoteIP:string", "RemotePort:int", "RemoteUrl:string", "LocalIP:string", "LocalPort:int", "Protocol:string", "InitiatingProcessFileName:string", "InitiatingProcessCommandLine:string", "InitiatingProcessId:long", "InitiatingProcessCreationTime:datetime", "InitiatingProcessUniqueId:string", "AdditionalFields:dynamic")),
            Table("DeviceLogonEvents", CommonDevice("ActionType:string", "LogonType:string", "Protocol:string", "AccountName:string", "AccountDomain:string", "AccountSid:string", "RemoteIP:string", "RemoteDeviceName:string", "FailureReason:string", "AdditionalFields:dynamic")),
            Table("DeviceRegistryEvents", CommonDevice("ActionType:string", "RegistryKey:string", "RegistryValueName:string", "RegistryValueData:string", "PreviousRegistryValueData:string", "InitiatingProcessFileName:string", "InitiatingProcessCommandLine:string")),
            Table("DeviceImageLoadEvents", CommonDevice("ActionType:string", "FileName:string", "FolderPath:string", "SHA1:string", "SHA256:string", "MD5:string", "InitiatingProcessFileName:string", "InitiatingProcessId:long")),
            Table("DeviceInfo", CommonDevice("OSPlatform:string", "OSVersion:string", "OSBuild:long", "DeviceType:string", "PublicIP:string", "IsAzureADJoined:bool", "LoggedOnUsers:dynamic", "AdditionalFields:dynamic")),
            Table("EmailEvents", Columns("Timestamp:datetime", "NetworkMessageId:string", "InternetMessageId:string", "SenderFromAddress:string", "SenderMailFromAddress:string", "RecipientEmailAddress:string", "Subject:string", "EmailDirection:string", "DeliveryAction:string", "DeliveryLocation:string", "ThreatTypes:string", "DetectionMethods:string", "ReportId:string")),
            Table("EmailAttachmentInfo", Columns("Timestamp:datetime", "NetworkMessageId:string", "FileName:string", "FileType:string", "SHA1:string", "SHA256:string", "FileSize:long", "ThreatTypes:string", "DetectionMethods:string", "ReportId:string")),
            Table("EmailUrlInfo", Columns("Timestamp:datetime", "NetworkMessageId:string", "Url:string", "UrlDomain:string", "ReportId:string")),
            Table("UrlClickEvents", Columns("Timestamp:datetime", "Url:string", "ActionType:string", "AccountUpn:string", "NetworkMessageId:string", "ThreatTypes:string", "ReportId:string")),
            Table("IdentityLogonEvents", Columns("Timestamp:datetime", "ActionType:string", "Application:string", "LogonType:string", "Protocol:string", "AccountName:string", "AccountDomain:string", "AccountUpn:string", "AccountSid:string", "IPAddress:string", "DeviceName:string", "FailureReason:string", "ReportId:string")),
            Table("IdentityDirectoryEvents", Columns("Timestamp:datetime", "ActionType:string", "Application:string", "AccountName:string", "AccountDomain:string", "AccountUpn:string", "AccountSid:string", "TargetAccountUpn:string", "TargetAccountDisplayName:string", "DeviceName:string", "AdditionalFields:dynamic", "ReportId:string")),
            Table("IdentityInfo", Columns("Timestamp:datetime", "AccountObjectId:string", "AccountUpn:string", "AccountDisplayName:string", "AccountName:string", "AccountDomain:string", "AccountSid:string", "Department:string", "JobTitle:string", "EmailAddress:string", "BlastRadius:string", "CriticalAssetDesignation:string")),
            Table("CloudAppEvents", Columns("Timestamp:datetime", "ActionType:string", "Application:string", "ApplicationId:int", "AccountObjectId:string", "AccountId:string", "AccountDisplayName:string", "IPAddress:string", "CountryCode:string", "UserAgent:string", "ActivityType:string", "ObjectName:string", "RawEventData:dynamic", "ReportId:string")),
            Table("AlertInfo", Columns("Timestamp:datetime", "AlertId:string", "Title:string", "Category:string", "Severity:string", "ServiceSource:string", "DetectionSource:string", "AttackTechniques:string")),
            Table("AlertEvidence", Columns("Timestamp:datetime", "AlertId:string", "EntityType:string", "EvidenceRole:string", "DeviceId:string", "DeviceName:string", "RemoteIP:string", "LocalIP:string", "AccountName:string", "AccountDomain:string", "AccountSid:string", "AccountObjectId:string", "FileName:string", "FolderPath:string", "SHA1:string", "SHA256:string", "AdditionalFields:dynamic")),
            Table("BehaviorInfo", Columns("Timestamp:datetime", "BehaviorId:string", "ActionType:string", "Title:string", "Description:string", "Categories:string", "AttackTechniques:string", "ServiceSource:string", "DetectionSource:string", "DataSources:string", "EntityType:string", "DeviceId:string", "AccountObjectId:string", "Insights:string", "AdditionalFields:dynamic")),
        })
        {
            if (tables.TryGetValue(table.Name, out var upstream))
            {
                var columns = upstream.Columns.ToDictionary(x => x.Name, StringComparer.OrdinalIgnoreCase);
                foreach (var column in table.Columns)
                    columns[column.Name] = column;
                tables[table.Name] = new SchemaTable(table.Name, columns.Values.ToArray());
            }
            else tables[table.Name] = table;
        }

        var functions = BuiltInFunctions().ToDictionary(x => x.Name, StringComparer.OrdinalIgnoreCase);
        return CreateSchema("xdr", tables, functions);
    }

    private static EnvironmentSchema BuildSentinel(string schemaDirectory)
    {
        var tables = LoadSchemaSnapshot("sentinel.json", schemaDirectory);
        if (tables.Count == 0)
        {
            foreach (var table in new[]
            {
                Table("SecurityAlert", Columns("TimeGenerated:datetime", "SystemAlertId:string", "DisplayName:string", "AlertName:string", "AlertSeverity:string", "Description:string", "ProviderName:string", "VendorName:string", "ProductName:string", "CompromisedEntity:string", "Entities:string", "ExtendedProperties:string", "Tactics:string", "Techniques:string")),
                Table("SecurityIncident", Columns("TimeGenerated:datetime", "IncidentNumber:int", "Title:string", "Description:string", "Severity:string", "Status:string", "Classification:string", "Owner:dynamic", "Labels:dynamic", "AlertIds:dynamic", "AdditionalData:dynamic")),
                Table("CommonSecurityLog", Columns("TimeGenerated:datetime", "DeviceVendor:string", "DeviceProduct:string", "DeviceVersion:string", "DeviceEventClassID:string", "Activity:string", "LogSeverity:string", "SourceIP:string", "SourcePort:int", "DestinationIP:string", "DestinationPort:int", "Protocol:string", "Message:string", "AdditionalExtensions:string")),
                Table("Syslog", Columns("TimeGenerated:datetime", "Facility:string", "SeverityLevel:string", "HostName:string", "ProcessID:int", "ProcessName:string", "SyslogMessage:string", "SourceSystem:string")),
                Table("SigninLogs", Columns("TimeGenerated:datetime", "Id:string", "UserPrincipalName:string", "UserId:string", "AppDisplayName:string", "AppId:string", "IPAddress:string", "ClientAppUsed:string", "ResultType:string", "ResultDescription:string", "Location:dynamic", "DeviceDetail:dynamic", "ConditionalAccessStatus:string", "RiskLevelDuringSignIn:string")),
                Table("AuditLogs", Columns("TimeGenerated:datetime", "Id:string", "Category:string", "OperationName:string", "Result:string", "ResultReason:string", "ActivityDisplayName:string", "InitiatedBy:dynamic", "TargetResources:dynamic", "AdditionalDetails:dynamic")),
                Table("AzureActivity", Columns("TimeGenerated:datetime", "OperationNameValue:string", "ActivityStatusValue:string", "ActivitySubstatusValue:string", "Caller:string", "CallerIpAddress:string", "CategoryValue:string", "ResourceGroup:string", "ResourceId:string", "SubscriptionId:string", "Properties:dynamic")),
                Table("Heartbeat", Columns("TimeGenerated:datetime", "Computer:string", "OSType:string", "OSName:string", "Version:string", "ComputerIP:string", "RemoteIPCountry:string", "SourceSystem:string")),
                Table("Watchlist", Columns("TimeGenerated:datetime", "WatchlistAlias:string", "SearchKey:string", "WatchlistItem:dynamic", "_DTItemId:string", "LastUpdatedTimeUTC:datetime")),
            })
                tables[table.Name] = table;
        }

        var functions = LoadFunctionSnapshot("sentinel-native-functions.json", schemaDirectory);
        foreach (var function in SentinelNativeFunctions.Create())
            functions[function.Key] = function.Value;
        return CreateSchema("sentinel", tables, functions);
    }

    private static EnvironmentSchema Merge(EnvironmentSchema xdr, EnvironmentSchema sentinel)
    {
        var tables = new Dictionary<string, SchemaTable>(sentinel.Tables, StringComparer.OrdinalIgnoreCase);
        foreach (var (name, table) in xdr.Tables)
        {
            if (!tables.TryGetValue(name, out var existing))
            {
                tables[name] = table;
                continue;
            }

            var columns = existing.Columns.ToDictionary(x => x.Name, StringComparer.OrdinalIgnoreCase);
            foreach (var column in table.Columns)
                columns[column.Name] = column;
            tables[name] = new SchemaTable(name, columns.Values.ToArray());
        }

        var functions = new Dictionary<string, SchemaFunction>(sentinel.Functions, StringComparer.OrdinalIgnoreCase);
        foreach (var function in xdr.Functions)
            functions[function.Key] = function.Value;
        return CreateSchema("unified", tables, functions);
    }

    private static EnvironmentSchema Apply(EnvironmentSchema schema, CatalogSection? overlay)
    {
        if (overlay is null) return schema;

        var tables = new Dictionary<string, SchemaTable>(schema.Tables, StringComparer.OrdinalIgnoreCase);
        foreach (var table in overlay.Tables)
        {
            if (!tables.TryGetValue(table.Name, out var existing))
            {
                tables[table.Name] = table;
                continue;
            }

            var columns = existing.Columns.ToDictionary(x => x.Name, StringComparer.OrdinalIgnoreCase);
            foreach (var column in table.Columns)
                columns[column.Name] = column;
            tables[table.Name] = new SchemaTable(existing.Name, columns.Values.ToArray());
        }

        var functions = new Dictionary<string, SchemaFunction>(schema.Functions, StringComparer.OrdinalIgnoreCase);
        foreach (var function in overlay.Functions)
            functions[function.Name] = function;
        return CreateSchema(schema.Name, tables, functions);
    }

    private static EnvironmentSchema CreateSchema(
        string name,
        IReadOnlyDictionary<string, SchemaTable> tables,
        IReadOnlyDictionary<string, SchemaFunction> functions) =>
        new(name, ContentVersion(name, tables, functions), tables, functions);

    private static string ContentVersion(
        string name,
        IReadOnlyDictionary<string, SchemaTable> tables,
        IReadOnlyDictionary<string, SchemaFunction> functions)
    {
        var canonical = new StringBuilder(name.ToLowerInvariant()).Append('\n');
        foreach (var table in tables.Values.OrderBy(x => x.Name, StringComparer.OrdinalIgnoreCase))
        {
            canonical.Append("table|").Append(table.Name.ToLowerInvariant()).Append('\n');
            foreach (var column in table.Columns.OrderBy(x => x.Name, StringComparer.OrdinalIgnoreCase))
                canonical.Append("column|").Append(column.Name.ToLowerInvariant()).Append('|').Append(column.Type.ToLowerInvariant()).Append('\n');
        }

        foreach (var function in functions.Values.OrderBy(x => x.Name, StringComparer.OrdinalIgnoreCase))
        {
            canonical.Append("function|").Append(function.Name.ToLowerInvariant()).Append('|')
                .Append(function.ScalarReturnType?.ToLowerInvariant()).Append('|')
                .Append(function.PreserveInput).Append('|').Append(function.RequiresTabularInput).Append('|')
                .Append(function.RequiredInputColumn?.ToLowerInvariant()).Append('|')
                .Append(function.RequiredInputType?.ToLowerInvariant()).Append('\n');
            foreach (var parameter in function.Parameters)
                canonical.Append("parameter|").Append(parameter.Name.ToLowerInvariant()).Append('|')
                    .Append(parameter.Type.ToLowerInvariant()).Append('|').Append(parameter.Optional).Append('\n');
            foreach (var column in (function.OutputColumns ?? []).OrderBy(x => x.Name, StringComparer.OrdinalIgnoreCase))
                canonical.Append("output|").Append(column.Name.ToLowerInvariant()).Append('|').Append(column.Type.ToLowerInvariant()).Append('\n');
        }

        var digest = SHA256.HashData(Encoding.UTF8.GetBytes(canonical.ToString()));
        return $"sha256:{Convert.ToHexString(digest.AsSpan(0, 12)).ToLowerInvariant()}";
    }

    private static IEnumerable<SchemaFunction> BuiltInFunctions()
    {
        yield return WatchlistFunction();
        yield return new("FileProfile", [new("fileColumn", "string", true), new("limit", "long", true)], Columns(
            "SHA1:string", "SHA256:string", "MD5:string", "FileSize:long", "GlobalPrevalence:long", "GlobalFirstSeen:datetime", "GlobalLastSeen:datetime",
            "Signer:string", "Issuer:string", "SignerHash:string", "IsCertificateValid:bool", "IsRootSignerMicrosoft:bool", "SignatureState:string",
            "IsExecutable:bool", "ThreatName:string", "Publisher:string", "SoftwareName:string", "ProfileAvailability:string"),
            PreserveInput: true, RequiresTabularInput: true);
        yield return new("DeviceFromIP", [new("ip", "string"), new("timestamp", "datetime", true)], Columns("IP:string", "DeviceId:string"), PreserveInput: true);
        yield return new("AssignedIPAddresses", [new("device", "string"), new("timestamp", "datetime", true)], Columns("Timestamp:datetime", "IPAddress:string", "IPType:string", "NetworkAdapterType:int", "ConnectedNetworks:dynamic"));
        yield return new("SeenBy", [new("deviceId", "string", true)], PreserveInput: true, RequiredInputColumn: "DeviceId", RequiredInputType: "string");
        yield return Behavior("GetFirstSeenBehaviors");
        yield return Behavior("GetUncommonValueBehaviors");
        yield return Behavior("GetHighVolumeAnomalyBehaviors");
        yield return Behavior("GetAnomalousBehaviorsByKind", new FunctionParameter("entityKind", "string"), new FunctionParameter("insightType", "string", true));
        yield return Behavior("GetAnomalousBehaviorsByValue", new FunctionParameter("entityValue", "string"), new FunctionParameter("insightType", "string", true));
        yield return Behavior("GetAnomalousBehaviorsAbout", new FunctionParameter("filters", "dynamic"));
    }

    private static SchemaFunction Behavior(string name, params FunctionParameter[] parameters) =>
        new(name, parameters, PreserveInput: true, RequiredInputColumn: "Insights", RequiredInputType: "string");

    private static SchemaFunction WatchlistFunction() =>
        new("_GetWatchlist", [new("watchlistAlias", "string")], Columns(
            "_DTItemId:string", "LastUpdatedTimeUTC:datetime", "SearchKey:string", "WatchlistAlias:string", "WatchlistItem:dynamic",
            "Asset Type:string", "Asset Id:string", "Asset Name:string", "Asset FQDN:string", "IP Address:string",
            "User Identifier:string", "User AAD Object Id:string", "User On-Prem Sid:string", "User Principal Name:string",
            "IP Subnet:string", "Range Name:string", "UserState:string", "Notification date:string", "Termination date:string",
            "Employee Id:string", "Email:string", "Associated Privileged Account ID:string", "Associated Privileged Account:string",
            "Service Identifier:string", "Service AAD Object Id:string", "Service On-Prem Sid:string", "Service Principal Name:string",
            "Owner User Identifier:string", "Owner User AAD Object Id:string", "Owner User On-Prem Sid:string", "Owner User Principal Name:string",
            "Tags:string"));

    private static SchemaTable Table(string name, IReadOnlyList<SchemaColumn> columns) => new(name, columns);

    private static IReadOnlyList<SchemaColumn> CommonDevice(params string[] extra) =>
        Columns(["Timestamp:datetime", "DeviceId:string", "DeviceName:string", "ReportId:long", .. extra]);

    private static IReadOnlyList<SchemaColumn> Columns(params string[] columns) => columns.Select(ParseColumn).ToArray();

    private static SchemaColumn ParseColumn(string value)
    {
        var separator = value.LastIndexOf(':');
        return separator < 0
            ? throw new InvalidDataException($"Schema column literal '{value}' must use the 'Name:type' form.")
            : new SchemaColumn(value[..separator], value[(separator + 1)..]);
    }

    private static Dictionary<string, SchemaTable> LoadSchemaSnapshot(string fileName, string schemaDirectory)
    {
        var tables = new Dictionary<string, SchemaTable>(StringComparer.OrdinalIgnoreCase);
        var path = Path.Combine(schemaDirectory, fileName);
        if (!File.Exists(path)) return tables;

        try
        {
            using var document = JsonDocument.Parse(File.ReadAllText(path));
            var root = document.RootElement;
            var sourceTables = root.ValueKind == JsonValueKind.Array ? root : root.GetProperty("tables");
            foreach (var table in sourceTables.EnumerateArray())
            {
                var name = GetString(table, "name", "Name");
                if (string.IsNullOrWhiteSpace(name)) continue;
                var schema = TryProperty(table, "columns", "Schema");
                if (schema is null) continue;
                var columns = schema.Value.EnumerateArray()
                    .Select(column => new SchemaColumn(
                        GetString(column, "name", "Name") ?? string.Empty,
                        NormalizeType(GetString(column, "type", "Type") ?? "string")))
                    .Where(column => !string.IsNullOrWhiteSpace(column.Name))
                    .GroupBy(column => column.Name, StringComparer.OrdinalIgnoreCase)
                    .Select(group => group.First())
                    .ToArray();
                tables[name] = new SchemaTable(name, columns);
            }
            return tables;
        }
        catch (Exception exception) when (exception is JsonException or KeyNotFoundException or InvalidOperationException)
        {
            throw new InvalidDataException($"Bundled schema snapshot '{fileName}' is malformed.", exception);
        }
    }

    private static Dictionary<string, SchemaFunction> LoadFunctionSnapshot(string fileName, string schemaDirectory)
    {
        var functions = new Dictionary<string, SchemaFunction>(StringComparer.OrdinalIgnoreCase);
        var path = Path.Combine(schemaDirectory, fileName);
        if (!File.Exists(path)) return functions;

        try
        {
            using var document = JsonDocument.Parse(File.ReadAllText(path));
            if (!document.RootElement.TryGetProperty("functions", out var sourceFunctions) || sourceFunctions.ValueKind != JsonValueKind.Array)
                return functions;
            foreach (var source in sourceFunctions.EnumerateArray())
            {
                var name = GetString(source, "name", "Name");
                if (string.IsNullOrWhiteSpace(name)) continue;
                var parameters = TryProperty(source, "parameters", "Parameters")?.EnumerateArray()
                    .Select(parameter => new FunctionParameter(
                        GetString(parameter, "name", "Name") ?? string.Empty,
                        NormalizeType(GetString(parameter, "type", "Type") ?? "string"),
                        TryProperty(parameter, "optional", "Optional")?.GetBoolean() ?? false))
                    .Where(parameter => !string.IsNullOrWhiteSpace(parameter.Name)).ToArray() ?? [];
                var output = TryProperty(source, "outputColumns", "OutputColumns")?.EnumerateArray()
                    .Select(column => new SchemaColumn(
                        GetString(column, "name", "Name") ?? string.Empty,
                        NormalizeType(GetString(column, "type", "Type") ?? "string")))
                    .Where(column => !string.IsNullOrWhiteSpace(column.Name)).ToArray() ?? [];
                functions[name] = new SchemaFunction(name, parameters, output);
            }
            return functions;
        }
        catch (Exception exception) when (exception is JsonException or KeyNotFoundException or InvalidOperationException)
        {
            throw new InvalidDataException($"Bundled schema snapshot '{fileName}' is malformed.", exception);
        }
    }

    private static IReadOnlySet<string> LoadActionTypes(string schemaDirectory)
    {
        var result = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var path = Path.Combine(schemaDirectory, "action-types.json");
        if (!File.Exists(path)) return result;

        try
        {
            using var document = JsonDocument.Parse(File.ReadAllText(path));
            var root = document.RootElement;
            var tables = root.ValueKind == JsonValueKind.Array ? root : root.GetProperty("tables");
            foreach (var table in tables.EnumerateArray())
            {
                var actions = TryProperty(table, "actionTypes", "ActionTypes");
                if (actions is null) continue;
                if (actions.Value.ValueKind == JsonValueKind.String && actions.Value.GetString() is { } single)
                    result.Add(single);
                else if (actions.Value.ValueKind == JsonValueKind.Array)
                    foreach (var action in actions.Value.EnumerateArray())
                        if (action.GetString() is { } value)
                            result.Add(value);
            }
            return result;
        }
        catch (Exception exception) when (exception is JsonException or KeyNotFoundException or InvalidOperationException)
        {
            throw new InvalidDataException("Bundled schema snapshot 'action-types.json' is malformed.", exception);
        }
    }

    private static JsonElement? TryProperty(JsonElement element, string camelCase, string pascalCase) =>
        element.TryGetProperty(camelCase, out var value) || element.TryGetProperty(pascalCase, out value) ? value : null;

    private static string? GetString(JsonElement element, string camelCase, string pascalCase) =>
        TryProperty(element, camelCase, pascalCase)?.GetString();

    private static string NormalizeType(string type) => type.ToLowerInvariant() switch
    {
        "int16" or "int32" or "integer" => "int",
        "int64" or "bigint" => "long",
        "boolean" => "bool",
        "object" or "array" => "dynamic",
        "float" or "double" or "decimal" => "real",
        "date" or "datetime" => "datetime",
        _ => ScalarTypes.GetSymbol(type.ToLowerInvariant()) is null ? "string" : type.ToLowerInvariant(),
    };
}
