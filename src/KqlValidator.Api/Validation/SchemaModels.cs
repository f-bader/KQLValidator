namespace KqlValidator.Validation;

public sealed record SchemaColumn(string Name, string Type,
    [property: System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    IReadOnlyList<ColumnObservation>? Observations = null);

public sealed record SchemaTable(string Name, IReadOnlyList<SchemaColumn> Columns);

public sealed record FunctionParameter(string Name, string Type, bool Optional = false);

public sealed record SchemaFunction(
    string Name,
    IReadOnlyList<FunctionParameter> Parameters,
    IReadOnlyList<SchemaColumn>? OutputColumns = null,
    string? ScalarReturnType = null,
    bool PreserveInput = false,
    string? RequiredInputColumn = null,
    string? RequiredInputType = null,
    bool RequiresTabularInput = false);

public sealed record EnvironmentSchema(
    string Name,
    string Version,
    IReadOnlyDictionary<string, SchemaTable> Tables,
    IReadOnlyDictionary<string, SchemaFunction> Functions);
