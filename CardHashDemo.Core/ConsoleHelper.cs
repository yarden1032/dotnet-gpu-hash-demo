namespace CardHashDemo.Core;

public static class ConsoleHelper
{
    public static void PrintHeader(string text)
    {
        string line = new('═', text.Length + 4);
        WriteColor(ConsoleColor.Cyan, $"╔{line}╗\n║  {text}  ║\n╚{line}╝");
        Console.WriteLine();
    }

    public static void PrintSection(string title)
    {
        Console.WriteLine();
        WriteColor(ConsoleColor.Yellow, $"▶ {title}");
        WriteColor(ConsoleColor.DarkGray, new string('─', title.Length + 2));
        Console.WriteLine();
    }

    public static void PrintInfo(string text) => Console.WriteLine($"  {text}");

    public static void PrintSuccess(string text) => WriteColor(ConsoleColor.Green, $"  ✓ {text}");

    public static void PrintWarning(string text) => WriteColor(ConsoleColor.Red, $"  ⚠ {text}");

    public static void PrintHighlight(string label, string value)
    {
        Console.ForegroundColor = ConsoleColor.Gray;
        Console.Write($"  {label}: ");
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine(value);
        Console.ResetColor();
    }

    public static void PrintResultRow(string label, string value)
    {
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.Write($"[RESULT] {label,-28}");
        Console.ForegroundColor = ConsoleColor.White;
        Console.WriteLine(value);
        Console.ResetColor();
    }

    public static void PrintComparisonTable(IEnumerable<(string Algorithm, TimeSpan Elapsed, double MHashSec)> rows)
    {
        Console.WriteLine();
        WriteColor(ConsoleColor.Yellow, "  " + new string('─', 72));
        WriteColor(ConsoleColor.Yellow, $"  {"Algorithm",-34} │ {"Elapsed",13} │ {"Speed",12}");
        WriteColor(ConsoleColor.Yellow, "  " + new string('─', 72));
        foreach (var (alg, elapsed, speed) in rows)
            WriteColor(ConsoleColor.White, $"  {alg,-34} │ {elapsed,13:hh\\:mm\\:ss\\.fff} │ {speed,9:F1} M/sec");
        WriteColor(ConsoleColor.Yellow, "  " + new string('─', 72));
        Console.WriteLine();
        WriteColor(ConsoleColor.Red, "  Salt defeats rainbow tables. It does NOT defeat brute force.");
        WriteColor(ConsoleColor.Red, "  Fix: use Argon2id or bcrypt with an appropriate work factor.");
        Console.WriteLine();
    }

    public static void PrintProgress(long tried, long total, TimeSpan elapsed, double mHashSec)
    {
        double pct = total > 0 ? tried * 100.0 / total : 0;
        Console.Write($"\r  [{pct,6:F2}%] {tried,13:N0} / {total:N0}  {mHashSec,6:F1} M/sec  {elapsed:hh\\:mm\\:ss\\.ff}   ");
    }

    public static void Pause(string message = "Press any key to continue...")
    {
        Console.WriteLine();
        WriteColor(ConsoleColor.DarkGray, $"  [{message}]");
        Console.ReadKey(true);
        Console.WriteLine();
    }

    private static void WriteColor(ConsoleColor color, string text)
    {
        Console.ForegroundColor = color;
        Console.WriteLine(text);
        Console.ResetColor();
    }
}
