using KqlValidator.Validation;

namespace KqlValidator.Tests;

internal static class TestSchemaCatalog
{
    // Tests that use the bundled schemas share this read-only catalog. Tests of
    // loading, custom directories, and overlays construct their own catalogs.
    public static SchemaCatalog Bundled { get; } = new();
}
