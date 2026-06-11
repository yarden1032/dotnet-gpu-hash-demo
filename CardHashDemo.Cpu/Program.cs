using System.Security.Cryptography;
using System.Text;
using CardHashDemo.Core;

Console.OutputEncoding = Encoding.UTF8;
Console.Clear();

ConsoleHelper.PrintHeader("SHA1 / SHA256 Credit Card Hash Vulnerability Demo  [CPU]");
ConsoleHelper.PrintWarning("EDUCATIONAL USE ONLY — authorized security testing / research");
ConsoleHelper.Pause();

// ── 1. SHA1 explainer ─────────────────────────────────────────────────────
DemoSections.PrintSha1Explainer();
ConsoleHelper.Pause();

// ── 2. Luhn algorithm ─────────────────────────────────────────────────────
DemoSections.PrintLuhnSection();
ConsoleHelper.Pause();

// ── 3. Israeli BINs ───────────────────────────────────────────────────────
DemoSections.PrintBinSection();
ConsoleHelper.Pause();

// ── Generate target card ──────────────────────────────────────────────────
ConsoleHelper.PrintSection("Generating Target Card");

var sixteenBins = IsraeliCards.KnownBins.Where(b => b.CardLength == 16).ToList();
var bin = sixteenBins[Random.Shared.Next(sixteenBins.Count)];
string card = IsraeliCards.GenerateCard(bin);

ConsoleHelper.PrintHighlight("Card (stored in payment system)", card);
ConsoleHelper.PrintHighlight("BIN", $"{bin.Prefix} — {bin.Issuer}");

byte[] cardAscii   = Encoding.ASCII.GetBytes(card);
byte[] staticSalt  = Encoding.UTF8.GetBytes("MySuperSecretPepper");
byte[] perCardSalt = new byte[16];
Random.Shared.NextBytes(perCardSalt);

string sha1Hash      = Convert.ToHexString(SHA1.HashData(cardAscii));
string sha256Hash    = Convert.ToHexString(SHA256.HashData(cardAscii));
string sha256Static  = Convert.ToHexString(SHA256.HashData([.. staticSalt,  .. cardAscii]));
string sha256PerCard = Convert.ToHexString(SHA256.HashData([.. perCardSalt, .. cardAscii]));

Console.WriteLine();
ConsoleHelper.PrintHighlight("SHA1(PAN)                   → stored in DB", sha1Hash);
ConsoleHelper.PrintHighlight("SHA256(PAN)                 → stored in DB", sha256Hash);
ConsoleHelper.PrintHighlight("SHA256(static-salt + PAN)   → stored in DB", sha256Static);
ConsoleHelper.PrintHighlight("SHA256(per-card-salt + PAN) → stored in DB", sha256PerCard);
ConsoleHelper.PrintHighlight("Per-card salt (also in DB row)",              Convert.ToHexString(perCardSalt));

Console.WriteLine();
ConsoleHelper.PrintInfo("Original card number is now 'forgotten'...");
ConsoleHelper.PrintInfo($"Attacker has: hash + knows it is an Israeli {bin.CardLength}-digit card");
ConsoleHelper.Pause("Press any key to start cracking...");

var prog = new Progress<CrackProgress>(p =>
    ConsoleHelper.PrintProgress(p.Tried, p.Total, p.Elapsed, p.MHashSec));

var results = new List<(string Algorithm, TimeSpan Elapsed, double MHashSec)>();

// ── Attack 1: SHA1, no salt ───────────────────────────────────────────────
ConsoleHelper.PrintSection("Attack 1 — SHA1 (no salt)");
ConsoleHelper.PrintInfo($"BIN {bin.Prefix} — iterating 10^{bin.CardLength - bin.Prefix.Length - 1} combinations...");
var r1 = await HashCracker.CrackAsync(sha1Hash, bin, HashAlgorithmName.SHA1,
    SaltMode.None, null, prog, default);
Console.WriteLine();
PrintResult("SHA1  (no salt)", r1, card);
results.Add(("SHA1  (no salt)", r1.Elapsed, r1.HashesPerSecond));
ConsoleHelper.Pause();

// ── Attack 2: SHA256, no salt ─────────────────────────────────────────────
ConsoleHelper.PrintSection("Attack 2 — SHA256 (no salt)");
ConsoleHelper.PrintInfo("Same attack, stronger algorithm. ~2× slower — still breaks in minutes.");
var r2 = await HashCracker.CrackAsync(sha256Hash, bin, HashAlgorithmName.SHA256,
    SaltMode.None, null, prog, default);
Console.WriteLine();
PrintResult("SHA256 (no salt)", r2, card);
results.Add(("SHA256 (no salt)", r2.Elapsed, r2.HashesPerSecond));
ConsoleHelper.Pause();

// ── Attack 3: SHA256, static salt ────────────────────────────────────────
ConsoleHelper.PrintSection("Attack 3 — SHA256 with static salt");
ConsoleHelper.PrintInfo("Salt: \"MySuperSecretPepper\" — known from leaked source code.");
ConsoleHelper.PrintInfo("Attacker prepends the salt to every candidate. Barely slower.");
var r3 = await HashCracker.CrackAsync(sha256Static, bin, HashAlgorithmName.SHA256,
    SaltMode.Static, staticSalt, prog, default);
Console.WriteLine();
PrintResult("SHA256 (static salt)", r3, card);
results.Add(("SHA256 (static salt)", r3.Elapsed, r3.HashesPerSecond));
ConsoleHelper.Pause();

// ── Attack 4: SHA256, per-card random salt ───────────────────────────────
ConsoleHelper.PrintSection("Attack 4 — SHA256 with per-card random salt");
ConsoleHelper.PrintInfo("Salt is random per card and stored alongside hash in the DB row.");
ConsoleHelper.PrintInfo("Attacker who stole the DB has both hash AND salt. Same speed.");
var r4 = await HashCracker.CrackAsync(sha256PerCard, bin, HashAlgorithmName.SHA256,
    SaltMode.PerCard, perCardSalt, prog, default);
Console.WriteLine();
PrintResult("SHA256 (per-card random salt)", r4, card);
results.Add(("SHA256 (per-card random salt, 16 B)", r4.Elapsed, r4.HashesPerSecond));
ConsoleHelper.Pause();

// ── Comparison table ──────────────────────────────────────────────────────
ConsoleHelper.PrintSection("Summary");
ConsoleHelper.PrintHighlight("Original card", card);
ConsoleHelper.PrintComparisonTable(results);

// ── Track 2 section ───────────────────────────────────────────────────────
DemoSections.PrintTrack2Section();
ConsoleHelper.Pause();

// ── Takeaways ─────────────────────────────────────────────────────────────
DemoSections.PrintTakeaways();

static void PrintResult(string label, CrackResult r, string expected)
{
    ConsoleHelper.PrintResultRow("Algorithm",          label);
    ConsoleHelper.PrintResultRow("Card found",         r.Card ?? "(not found)");
    if (r.Card == expected) ConsoleHelper.PrintSuccess("Matches the original card ✓");
    else                    ConsoleHelper.PrintWarning("Mismatch — check output!");
    ConsoleHelper.PrintResultRow("Elapsed",            r.Elapsed.ToString(@"hh\:mm\:ss\.fff"));
    ConsoleHelper.PrintResultRow("Speed",              $"{r.HashesPerSecond:F1} M hash/sec");
    ConsoleHelper.PrintResultRow("Combinations tried", $"{r.Tried:N0} / {r.Total:N0}");
}
