namespace KqlValidator.Validation;

internal static class AzureMonitorTransformationFeatures
{
    public static IReadOnlySet<string> AllowedPipeOperators { get; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "extend", "project", "where", "parse", "print", "project-away", "project-rename",
    };

    public static IReadOnlySet<string> AllowedFunctions { get; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "abs", "ago", "array_concat", "array_length", "base64_decodestring", "base64_encodestring",
        "binary_and", "binary_not", "binary_or", "binary_shift_left", "binary_shift_right", "binary_xor",
        "bin", "bool", "case", "ceiling", "columnifexists", "countof", "datatable", "datetime", "datetime_add",
        "datetime_diff", "datetime_part", "dayofmonth", "dayofweek", "dayofyear", "decimal", "dynamic",
        "endofday", "endofmonth", "endofweek", "endofyear", "exp", "exp10", "exp2", "extract", "extract_all",
        "floor", "geo_location", "getmonth", "gettype", "getyear", "guid", "hash_sha256", "hour", "hourofday",
        "iff", "iif", "indexof", "ingestion_time", "int", "isfinite", "isempty", "isinf", "isnan", "isnotempty",
        "isnotnull", "isnull", "log", "log10", "log2", "long", "make_datetime", "make_timespan", "max_of",
        "min_of", "monthofyear", "now", "pack", "pack_array", "parse_cef_dictionary", "parse_json", "parse_xml",
        "pow", "real", "replace", "round", "sign", "split", "startofday", "startofmonth", "startofweek",
        "startofyear", "strcat", "strcat_delim", "strlen", "substring", "tobool", "todatetime", "todouble",
        "toguid", "toint", "tolong", "toreal", "tostring", "totimespan", "toupper", "tolower", "weekofyear", "zip",
    };

    public static IReadOnlySet<string> ScalarTypes { get; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "bool", "datetime", "decimal", "dynamic", "guid", "int", "long", "real", "string", "timespan",
    };

    public static IReadOnlySet<string> ParenthesizedOperators { get; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "between", "in",
    };
}
