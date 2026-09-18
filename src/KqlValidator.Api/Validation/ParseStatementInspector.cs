using System.Text.RegularExpressions;
using Kusto.Language.Syntax;

namespace KqlValidator.Validation;

internal static class ParseStatementInspector
{
    public static IReadOnlyList<ParseStatementInfo> Find(SyntaxNode syntax, CancellationToken cancellationToken)
    {
        var statements = new List<ParseStatementInfo>();
        SyntaxElement.WalkNodes(syntax, node =>
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (node is not ParseOperator parse)
                return;

            var count = 0;
            SyntaxElement.WalkNodes(parse, child =>
            {
                if (child.Kind == SyntaxKind.NameDeclaration)
                    count++;
            });
            statements.Add(new(parse.TextStart, parse.Width, count,
                Regex.IsMatch(parse.ToString(), @"(?i)\bkind\s*=\s*regex\b", RegexOptions.CultureInvariant,
                    TimeSpan.FromMilliseconds(250))));
        });
        return statements;
    }
}

internal sealed record ParseStatementInfo(int Start, int Length, int ExtractionCount, bool IsRegex);
