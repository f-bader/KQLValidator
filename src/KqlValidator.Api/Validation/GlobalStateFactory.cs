using KqlValidator.Contracts;
using Kusto.Language;
using Kusto.Language.Symbols;

namespace KqlValidator.Validation;

public sealed class GlobalStateFactory
{
    public GlobalState Create(EnvironmentSchema schema, ValidationExtensions? extensions)
    {
        var members = new List<Symbol>();
        members.AddRange(schema.Tables.Values.Select(ToTable));
        foreach (var schemaFunction in schema.Functions.Values)
        {
            var function = schemaFunction;
            if (function.Name.Equals("_GetWatchlist", StringComparison.OrdinalIgnoreCase) && extensions?.Watchlists is { Count: > 0 })
            {
                var extra = extensions.Watchlists.SelectMany(x => x.Columns)
                    .GroupBy(x => x.Name, StringComparer.OrdinalIgnoreCase)
                    .Select(x => new SchemaColumn(x.Key, x.First().Type));
                function = function with { OutputColumns = [.. function.OutputColumns ?? [], .. extra] };
            }
            members.Add(ToFunction(function));
        }

        if (extensions?.Tables is not null)
            members.AddRange(extensions.Tables.Select(x => ToTable(new SchemaTable(x.Name, x.Columns.Select(c => new SchemaColumn(c.Name, c.Type)).ToArray()))));
        if (extensions?.Functions is not null)
            members.AddRange(extensions.Functions.Select(ToFunction));

        return GlobalState.Default.WithDatabase(new DatabaseSymbol("KqlValidator", members));
    }

    private static TableSymbol ToTable(SchemaTable table) =>
        new(table.Name, table.Columns.Select(x => new ColumnSymbol(x.Name, ResolveType(x.Type))));

    private static FunctionSymbol ToFunction(SchemaFunction function)
    {
        var parameters = function.Parameters.Select(ToParameter).ToArray();

        if (function.RequiredInputColumn is not null || function.RequiresTabularInput)
        {
            var rowType = function.RequiredInputColumn is null
                ? new TableSymbol(Array.Empty<ColumnSymbol>())
                : new TableSymbol(new ColumnSymbol(function.RequiredInputColumn, ResolveType(function.RequiredInputType!)));
            var invokeParameters = new[] { new Parameter("T", rowType) }.Concat(parameters).ToArray();
            return new FunctionSymbol(
                function.Name,
                context =>
                {
                    var input = context.ArgumentTypes.OfType<TableSymbol>().FirstOrDefault() ?? context.RowScope;
                    var columns = function.OutputColumns?.Select(x => new ColumnSymbol(x.Name, ResolveType(x.Type))).ToArray() ?? [];
                    if (!function.PreserveInput || input is null) return new TableSymbol(columns);
                    return new TableSymbol(input.Members.OfType<ColumnSymbol>().Concat(columns))
                        .WithInheritableProperties(input);
                },
                Tabularity.Tabular,
                invokeParameters);
        }

        if (function.ScalarReturnType is not null)
            return new FunctionSymbol(function.Name, ResolveType(function.ScalarReturnType), parameters);

        return new FunctionSymbol(
            function.Name,
            context =>
            {
                var columns = function.OutputColumns?.Select(x => new ColumnSymbol(x.Name, ResolveType(x.Type))).ToArray() ?? [];
                var output = new TableSymbol(columns);
                if (!function.PreserveInput || context.RowScope is null)
                    return output;
                return new TableSymbol(context.RowScope.Members.OfType<ColumnSymbol>().Concat(columns))
                    .WithInheritableProperties(context.RowScope);
            },
            Tabularity.Tabular,
            parameters);
    }

    private static FunctionSymbol ToFunction(FunctionDeclaration function)
    {
        var parameters = function.Parameters?.Select(x => new FunctionParameter(x.Name, x.Type, x.Optional)).ToArray() ?? [];
        var declaration = new SchemaFunction(
            function.Name,
            parameters,
            function.Returns.Columns?.Select(x => new SchemaColumn(x.Name, x.Type)).ToArray(),
            function.Returns.Kind.Equals("scalar", StringComparison.OrdinalIgnoreCase) ? function.Returns.Type : null,
            function.Returns.PreserveInput,
            RequiresTabularInput: function.Returns.PreserveInput);
        return ToFunction(declaration);
    }

    private static Parameter ToParameter(FunctionParameter parameter) =>
        new(parameter.Name, ResolveType(parameter.Type), minOccurring: parameter.Optional ? 0 : 1);

    public static ScalarSymbol ResolveType(string type) => ScalarTypes.GetSymbol(type.ToLowerInvariant())
        ?? throw new ArgumentException($"Unsupported KQL scalar type '{type}'.");
}
