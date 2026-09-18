using System.Text.Json;
using System.Text.RegularExpressions;
using KqlValidator.Contracts;

namespace KqlValidator.Validation;

/// <summary>Strict, startup-only parser for a deployer's schema declarations.</summary>
internal sealed partial class CustomSchemaOverlay
{
    private CustomSchemaOverlay(CatalogSection common, IReadOnlyDictionary<KqlEnvironment, CatalogSection> environments)
    {
        Common = common;
        Environments = environments;
    }

    public CatalogSection Common { get; }
    public IReadOnlyDictionary<KqlEnvironment, CatalogSection> Environments { get; }

    public static CustomSchemaOverlay Load(string path)
    {
        try
        {
            if (!File.Exists(path))
                throw new InvalidDataException($"Custom schema catalog '{path}' does not exist.");

            using var document = JsonDocument.Parse(File.ReadAllText(path));
            var root = document.RootElement;
            RequireObject(root, "root");
            EnsureProperties(root, "root", "common", "environments");
            var common = ParseSection(RequiredProperty(root, "common", "root"), "common");
            var environmentElement = RequiredProperty(root, "environments", "root");
            RequireObject(environmentElement, "environments");
            EnsureProperties(environmentElement, "environments", "xdr", "sentinel", "unified");

            var environments = new Dictionary<KqlEnvironment, CatalogSection>();
            foreach (var (name, environment) in new[]
            {
                ("xdr", KqlEnvironment.Xdr),
                ("sentinel", KqlEnvironment.Sentinel),
                ("unified", KqlEnvironment.Unified),
            })
            {
                if (environmentElement.TryGetProperty(name, out var section))
                    environments.Add(environment, ParseSection(section, $"environments.{name}"));
            }

            return new CustomSchemaOverlay(common, environments);
        }
        catch (InvalidDataException)
        {
            throw;
        }
        catch (Exception exception) when (exception is IOException or JsonException or InvalidOperationException)
        {
            throw new InvalidDataException($"Custom schema catalog '{path}' is malformed: {exception.Message}", exception);
        }
    }

    private static CatalogSection ParseSection(JsonElement element, string location)
    {
        RequireObject(element, location);
        EnsureProperties(element, location, "tables", "functions");
        var tables = element.TryGetProperty("tables", out var tableElements)
            ? ParseTables(tableElements, location)
            : [];
        var functions = element.TryGetProperty("functions", out var functionElements)
            ? ParseFunctions(functionElements, location)
            : [];

        var names = new HashSet<string>(tables.Select(x => x.Name), StringComparer.OrdinalIgnoreCase);
        if (functions.Any(function => !names.Add(function.Name)))
            throw Error(location, "A table and function cannot share a name within one section.");
        return new CatalogSection(tables, functions);
    }

    private static IReadOnlyList<SchemaTable> ParseTables(JsonElement element, string location)
    {
        RequireArray(element, $"{location}.tables");
        var tables = new List<SchemaTable>();
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var item in element.EnumerateArray())
        {
            RequireObject(item, $"{location}.tables[]");
            EnsureProperties(item, $"{location}.tables[]", "name", "columns");
            var name = RequiredString(item, "name", $"{location}.tables[]");
            ValidateIdentifier(name, "table name", location);
            if (!names.Add(name))
                throw Error(location, $"Duplicate table declaration '{name}'.");
            var columns = ParseColumns(RequiredProperty(item, "columns", $"table '{name}'"), $"table '{name}'");
            if (columns.Count == 0)
                throw Error(location, $"Table '{name}' requires a complete, non-empty columns collection.");
            tables.Add(new SchemaTable(name, columns));
        }
        return tables;
    }

    private static IReadOnlyList<SchemaFunction> ParseFunctions(JsonElement element, string location)
    {
        RequireArray(element, $"{location}.functions");
        var functions = new List<SchemaFunction>();
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var item in element.EnumerateArray())
        {
            RequireObject(item, $"{location}.functions[]");
            EnsureProperties(item, $"{location}.functions[]", "name", "parameters", "returns");
            var name = RequiredString(item, "name", $"{location}.functions[]");
            ValidateIdentifier(name, "function name", location);
            if (!names.Add(name))
                throw Error(location, $"Duplicate function declaration '{name}'.");

            var parameters = item.TryGetProperty("parameters", out var parameterElement)
                ? ParseParameters(parameterElement, name, location)
                : [];
            var returns = RequiredProperty(item, "returns", $"function '{name}'");
            RequireObject(returns, $"function '{name}'.returns");
            EnsureProperties(returns, $"function '{name}'.returns", "kind", "type", "columns", "preserveInput");
            var kind = RequiredString(returns, "kind", $"function '{name}'.returns");
            var preserveInput = OptionalBoolean(returns, "preserveInput", $"function '{name}'.returns") ?? false;
            if (kind.Equals("scalar", StringComparison.OrdinalIgnoreCase))
            {
                if (preserveInput || returns.TryGetProperty("columns", out _))
                    throw Error(location, $"Scalar function '{name}' cannot have columns or preserve input.");
                var type = RequiredString(returns, "type", $"scalar function '{name}'.returns");
                ValidateType(type, $"function '{name}' return type", location);
                functions.Add(new SchemaFunction(name, parameters, ScalarReturnType: type.ToLowerInvariant()));
            }
            else if (kind.Equals("tabular", StringComparison.OrdinalIgnoreCase))
            {
                if (returns.TryGetProperty("type", out _))
                    throw Error(location, $"Tabular function '{name}' cannot have a scalar return type.");
                var columns = ParseColumns(RequiredProperty(returns, "columns", $"tabular function '{name}'.returns"), $"function '{name}' return");
                functions.Add(new SchemaFunction(name, parameters, columns, PreserveInput: preserveInput,
                    RequiresTabularInput: preserveInput));
            }
            else
                throw Error(location, $"Function '{name}' return kind must be scalar or tabular.");
        }
        return functions;
    }

    private static IReadOnlyList<FunctionParameter> ParseParameters(JsonElement element, string function, string location)
    {
        RequireArray(element, $"function '{function}'.parameters");
        var result = new List<FunctionParameter>();
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var optionalSeen = false;
        foreach (var item in element.EnumerateArray())
        {
            RequireObject(item, $"function '{function}'.parameters[]");
            EnsureProperties(item, $"function '{function}'.parameters[]", "name", "type", "optional");
            var name = RequiredString(item, "name", $"function '{function}'.parameters[]");
            var type = RequiredString(item, "type", $"parameter '{name}'");
            var optional = OptionalBoolean(item, "optional", $"parameter '{name}'") ?? false;
            ValidateIdentifier(name, "parameter name", location);
            ValidateType(type, $"parameter '{name}'", location);
            if (!names.Add(name)) throw Error(location, $"Function '{function}' has duplicate parameter '{name}'.");
            if (!optional && optionalSeen) throw Error(location, $"Required parameter '{name}' cannot follow an optional parameter.");
            optionalSeen |= optional;
            result.Add(new FunctionParameter(name, type.ToLowerInvariant(), optional));
        }
        return result;
    }

    private static IReadOnlyList<SchemaColumn> ParseColumns(JsonElement element, string owner)
    {
        RequireArray(element, $"{owner}.columns");
        var result = new List<SchemaColumn>();
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var item in element.EnumerateArray())
        {
            RequireObject(item, $"{owner}.columns[]");
            EnsureProperties(item, $"{owner}.columns[]", "name", "type");
            var name = RequiredString(item, "name", $"{owner}.columns[]");
            var type = RequiredString(item, "type", $"column '{name}'");
            ValidateIdentifier(name, "column name", owner);
            ValidateType(type, $"column '{name}'", owner);
            if (!names.Add(name)) throw Error(owner, $"The {owner} has duplicate column '{name}'.");
            result.Add(new SchemaColumn(name, type.ToLowerInvariant()));
        }
        return result;
    }

    private static void ValidateIdentifier(string value, string kind, string location)
    {
        if (value.Length > 128 || !Identifier().IsMatch(value))
            throw Error(location, $"'{value}' is not a valid {kind}.");
    }

    private static void ValidateType(string type, string field, string location)
    {
        try { _ = GlobalStateFactory.ResolveType(type); }
        catch (ArgumentException) { throw Error(location, $"The {field} requires a supported KQL scalar type."); }
    }

    private static JsonElement RequiredProperty(JsonElement element, string property, string owner) =>
        element.TryGetProperty(property, out var value)
            ? value
            : throw Error(owner, $"Property '{property}' is required.");

    private static string RequiredString(JsonElement element, string property, string owner)
    {
        var value = RequiredProperty(element, property, owner);
        if (value.ValueKind != JsonValueKind.String || string.IsNullOrWhiteSpace(value.GetString()))
            throw Error(owner, $"Property '{property}' must be a non-empty string.");
        return value.GetString()!;
    }

    private static bool? OptionalBoolean(JsonElement element, string property, string owner)
    {
        if (!element.TryGetProperty(property, out var value)) return null;
        if (value.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
            throw Error(owner, $"Property '{property}' must be a boolean.");
        return value.GetBoolean();
    }

    private static void EnsureProperties(JsonElement element, string owner, params string[] allowed)
    {
        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in element.EnumerateObject())
        {
            if (!names.Add(property.Name)) throw Error(owner, $"Duplicate property '{property.Name}'.");
            if (!allowed.Contains(property.Name, StringComparer.Ordinal))
                throw Error(owner, $"Unknown property '{property.Name}'.");
        }
    }

    private static void RequireObject(JsonElement element, string owner)
    {
        if (element.ValueKind != JsonValueKind.Object) throw Error(owner, "Expected an object.");
    }

    private static void RequireArray(JsonElement element, string owner)
    {
        if (element.ValueKind != JsonValueKind.Array) throw Error(owner, "Expected an array.");
    }

    private static InvalidDataException Error(string location, string message) =>
        new($"Custom schema catalog {location}: {message}");

    [GeneratedRegex(@"^[A-Za-z_][A-Za-z0-9_]*$")]
    private static partial Regex Identifier();
}

internal sealed record CatalogSection(IReadOnlyList<SchemaTable> Tables, IReadOnlyList<SchemaFunction> Functions);
