namespace CardHashDemo.Core;

public static class DemoSections
{
    public static void PrintSha1Explainer()
    {
        ConsoleHelper.PrintSection("What is SHA1?");
        ConsoleHelper.PrintInfo("SHA1 (Secure Hash Algorithm 1) was designed by the NSA, published by NIST in 1995.");
        ConsoleHelper.PrintInfo("It produces a 160-bit (40 hex char) digest from any input.");
        ConsoleHelper.PrintInfo("");
        ConsoleHelper.PrintInfo("Properties that make it FAST — by design:");
        ConsoleHelper.PrintInfo("  • Software : ~500 MB/sec single-threaded on a modern CPU");
        ConsoleHelper.PrintInfo("  • GPU      : ~20 BILLION hashes/sec for short inputs (RTX 3080)");
        ConsoleHelper.PrintInfo("");
        ConsoleHelper.PrintInfo("Why SHA1 is broken for card data:");
        ConsoleHelper.PrintInfo("  1. No salt  — identical inputs always produce identical outputs");
        ConsoleHelper.PrintInfo("  2. Deterministic — attacker can precompute or brute-force");
        ConsoleHelper.PrintInfo("  3. SHAttered (2017) — chosen-prefix collision attack is practical");
        ConsoleHelper.PrintInfo("  4. Tiny input space — card numbers are heavily constrained");
        ConsoleHelper.PrintInfo("");
        ConsoleHelper.PrintWarning("PCI-DSS v4.0 §3.5: Strong cryptography required. SHA1 alone does NOT qualify.");
    }

    public static void PrintLuhnSection()
    {
        ConsoleHelper.PrintSection("The Luhn Algorithm (ISO/IEC 7812)");
        ConsoleHelper.PrintInfo("Also called 'mod 10'. Purpose: detect transcription errors — NOT security.");
        ConsoleHelper.PrintInfo("");
        ConsoleHelper.PrintInfo("Structure of a 16-digit card:");
        ConsoleHelper.PrintInfo("  • Digits 1-6   = BIN — Bank Identification Number (identifies issuer)");
        ConsoleHelper.PrintInfo("  • Digits 7-15  = account number (9 free digits)");
        ConsoleHelper.PrintInfo("  • Digit  16    = Luhn check digit — FULLY DETERMINED by digits 1-15");
        ConsoleHelper.PrintInfo("");
        ConsoleHelper.PrintInfo("Consequence for an attacker:");
        ConsoleHelper.PrintInfo("  Without any knowledge:     10^16 = 10,000,000,000,000,000 candidates");
        ConsoleHelper.PrintInfo("  Knowing the BIN (6 digits):  10^9 =         1,000,000,000 candidates");
        ConsoleHelper.PrintInfo("  Luhn just determines last digit — search space stays 10^9 per BIN");
        ConsoleHelper.PrintInfo("");
        ConsoleHelper.PrintHighlight("Knowing the BIN cuts search space", "by a factor of 10,000,000");
        Console.WriteLine();

        ConsoleHelper.PrintInfo("Live Luhn demo:");
        bool v1 = LuhnAlgorithm.Validate("4111111111111111".AsSpan());
        bool v2 = LuhnAlgorithm.Validate("4111111111111112".AsSpan());
        if (v1)  ConsoleHelper.PrintSuccess("4111111111111111  →  VALID  ✓");
        if (!v2) ConsoleHelper.PrintSuccess("4111111111111112  →  INVALID (check digit off by 1)  ✓");
    }

    public static void PrintBinSection()
    {
        int total16 = IsraeliCards.KnownBins.Count(b => b.CardLength == 16);
        int total15 = IsraeliCards.KnownBins.Count(b => b.CardLength == 15);
        int total14 = IsraeliCards.KnownBins.Count(b => b.CardLength == 14);

        ConsoleHelper.PrintSection("Known Israeli Card BIN Prefixes");
        ConsoleHelper.PrintInfo($"Knowing the card is Israeli constrains the first 6 digits to one of {IsraeliCards.KnownBins.Count} known BINs.");
        ConsoleHelper.PrintInfo("(Approximate list — for educational use only)");
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Gray;
        Console.WriteLine($"  {"Prefix",-8} {"Issuer",-38} {"Digits",6}");
        Console.WriteLine($"  {new string('─', 56)}");
        foreach (var b in IsraeliCards.KnownBins)
            Console.WriteLine($"  {b.Prefix,-8} {b.Issuer,-38} {b.CardLength,6}");
        Console.ResetColor();
        Console.WriteLine();
        ConsoleHelper.PrintHighlight("16-digit BINs (Visa / Mastercard)",  $"{total16}  →  {total16:N0} × 10^9 = {(long)total16 * 1_000_000_000L:N0} candidates");
        if (total15 > 0)
            ConsoleHelper.PrintHighlight("15-digit BINs (Amex)",           $"{total15}  →  {total15:N0} × 10^9 = {(long)total15 * 1_000_000_000L:N0} candidates");
        if (total14 > 0)
            ConsoleHelper.PrintHighlight("14-digit BINs (Diners)",         $"{total14}  →  {total14:N0} × 10^8 = {(long)total14 * 100_000_000L:N0} candidates");
        ConsoleHelper.PrintHighlight("Total search space (all 16-digit)",  $"~{(long)total16 * 1_000_000_000L:N0}");
    }

    /// <param name="attacks">Results from the PAN cracking runs. HashesPerSecond in M/sec for CPU, G/sec×1000 for GPU.</param>
    /// <param name="isGpu">True when speeds are in billions/sec rather than millions/sec.</param>
    public static void PrintTrack2Section(IReadOnlyList<AttackResult> attacks, bool isGpu = false)
    {
        ConsoleHelper.PrintSection("What About SHA1( Track 2 )?");
        ConsoleHelper.PrintInfo("Track 2 is the full magnetic stripe payload:");
        ConsoleHelper.PrintHighlight("Format ", ";PAN=YYMM SC DISC?");
        ConsoleHelper.PrintHighlight("Example", ";4362011234567894=2512101000000000?");
        Console.WriteLine();
        ConsoleHelper.PrintInfo("Expanded search space per BIN:");
        ConsoleHelper.PrintInfo($"  PAN combinations                   :   {ResultSummary.PanCombinations:N0}  (10^9)");
        ConsoleHelper.PrintInfo($"  Expiry dates (6 yrs × 12 months)   :   {ResultSummary.ExpiryDatesAll} values");
        ConsoleHelper.PrintInfo($"  Service codes (common set)         :   {ResultSummary.ServiceCodes} values");
        ConsoleHelper.PrintInfo( "  Discretionary data                 :   often zeros or constant");
        Console.WriteLine();
        ConsoleHelper.PrintHighlight("Full Track2 space per BIN",
            $"{ResultSummary.Track2Full:N0}  (~10^12)");
        ConsoleHelper.PrintHighlight("With known expiry year",
            $"{ResultSummary.Track2KnownYear:N0}  (~1.8×10^11)");
        Console.WriteLine();

        // ── Extrapolate from measured speeds ──────────────────────────────
        ConsoleHelper.PrintInfo("Estimated crack time based on YOUR measured speeds:");
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine($"  {"Algorithm",-38} │ {"Speed",12} │ {"Full Track2",15} │ {"Known year",13}");
        Console.WriteLine($"  {new string('─', 88)}");
        Console.ResetColor();

        foreach (var a in attacks)
        {
            // HashesPerSecond is always stored in M/sec (millions) in AttackResult
            double hps  = a.HashesPerSecond * 1_000_000.0;
            string t1   = ResultSummary.FormatDuration(ResultSummary.Track2Full      / hps);
            string t2   = ResultSummary.FormatDuration(ResultSummary.Track2KnownYear / hps);
            string speedLabel = isGpu
                ? $"{a.HashesPerSecond / 1000.0:F3} G/sec"
                : $"{a.HashesPerSecond:F1} M/sec";
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine($"  {a.Algorithm,-38} │ {speedLabel,12} │ {t1,15} │ {t2,13}");
        }
        Console.ResetColor();
        Console.WriteLine();
        ConsoleHelper.PrintWarning("Conclusion: SHA1(Track2) is still crackable on this machine — just slower.");
    }

    public static void PrintTakeaways()
    {
        ConsoleHelper.PrintSection("Key Takeaways");
        ConsoleHelper.PrintWarning("NEVER hash card data with SHA1, SHA256, or any fast hash — with or without salt.");
        Console.WriteLine();
        ConsoleHelper.PrintInfo("The root problem is SPEED, not algorithm strength:");
        ConsoleHelper.PrintInfo("  SHA1   = ~500M hash/sec  → trivially fast");
        ConsoleHelper.PrintInfo("  SHA256 = ~250M hash/sec  → still trivially fast");
        ConsoleHelper.PrintInfo("  Salt defeats rainbow tables, NOT targeted brute force");
        ConsoleHelper.PrintInfo("  Per-card random salt + SHA256: attacker who has the DB row has BOTH hash and salt");
        Console.WriteLine();
        ConsoleHelper.PrintInfo("Correct approaches:");
        ConsoleHelper.PrintSuccess("Tokenization: store a random token mapped to the PAN in a PCI-scoped vault");
        ConsoleHelper.PrintSuccess("Encryption  : AES-256 with proper key management — reversible by design");
        ConsoleHelper.PrintSuccess("If you MUST hash: Argon2id or bcrypt with a work factor (slow by design)");
        Console.WriteLine();
        ConsoleHelper.PrintHighlight("PCI-DSS v4.0 reference", "Requirement 3.5 — protecting stored account data");
    }
}
