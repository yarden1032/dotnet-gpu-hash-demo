using System.Security.Cryptography;
using System.Text;

namespace CardHashDemo.Core;

public enum SaltMode { None, Static, PerCard }

public record CrackResult(string? Card, TimeSpan Elapsed, long Tried, long Total, double HashesPerSecond);

public record CrackProgress(long Tried, long Total, TimeSpan Elapsed, double MHashSec);

public static class HashCracker
{
    public static Task<CrackResult> CrackAsync(
        string targetHashHex,
        BinEntry bin,
        HashAlgorithmName algorithm,
        SaltMode saltMode,
        byte[]? salt,
        IProgress<CrackProgress>? progress,
        CancellationToken ct)
    {
        return Task.Run(() => RunCrack(targetHashHex, bin, algorithm, saltMode, salt ?? [], progress, ct), ct);
    }

    private static CrackResult RunCrack(
        string targetHashHex,
        BinEntry bin,
        HashAlgorithmName algorithm,
        SaltMode saltMode,
        byte[] salt,
        IProgress<CrackProgress>? progress,
        CancellationToken ct)
    {
        int freeDigits = bin.CardLength - bin.Prefix.Length - 1;
        long totalCombinations = 1;
        for (int i = 0; i < freeDigits; i++) totalCombinations *= 10;

        byte[] targetHash = Convert.FromHexString(targetHashHex);
        byte[] binBytes   = Encoding.ASCII.GetBytes(bin.Prefix);
        bool isSha256     = algorithm == HashAlgorithmName.SHA256;

        string? foundCard = null;
        long    processed = 0;
        var     sw        = System.Diagnostics.Stopwatch.StartNew();

        var opts = new ParallelOptions
        {
            MaxDegreeOfParallelism = Environment.ProcessorCount,
            CancellationToken      = ct,
        };

        try
        {
            Parallel.For(0L, totalCombinations, opts, (i, state) =>
            {
                if (state.ShouldExitCurrentIteration) return;

                // Build ASCII card bytes — zero allocation, all on stack
                Span<byte> cardBytes = stackalloc byte[bin.CardLength];

                for (int j = 0; j < binBytes.Length; j++) cardBytes[j] = binBytes[j];

                long val = i;
                for (int j = bin.CardLength - 2; j >= binBytes.Length; j--)
                {
                    cardBytes[j] = (byte)('0' + val % 10);
                    val /= 10;
                }

                cardBytes[bin.CardLength - 1] = (byte)('0' + LuhnAlgorithm.ComputeCheckDigit(cardBytes[..^1]));

                // Build hash input: salt || card
                int inputLen = salt.Length + bin.CardLength;
                Span<byte> inputBytes = stackalloc byte[inputLen];
                salt.CopyTo(inputBytes);
                cardBytes.CopyTo(inputBytes[salt.Length..]);

                // Compute hash and compare
                Span<byte> hashBytes = stackalloc byte[32];
                int hashLen = isSha256
                    ? SHA256.HashData(inputBytes, hashBytes)
                    : SHA1.HashData(inputBytes, hashBytes);

                if (hashBytes[..hashLen].SequenceEqual(targetHash))
                {
                    foundCard = Encoding.ASCII.GetString(cardBytes);
                    state.Stop();
                }

                long p = Interlocked.Add(ref processed, 1);
                if (p % 500_000 == 0 && progress is not null)
                {
                    double sec  = sw.Elapsed.TotalSeconds;
                    double mhps = sec > 0 ? p / sec / 1_000_000.0 : 0;
                    progress.Report(new CrackProgress(p, totalCombinations, sw.Elapsed, mhps));
                }
            });
        }
        catch (OperationCanceledException) { }

        sw.Stop();
        long tried       = Interlocked.Read(ref processed);
        double mhpsFinal = sw.Elapsed.TotalSeconds > 0 ? tried / sw.Elapsed.TotalSeconds / 1_000_000.0 : 0;
        return new CrackResult(foundCard, sw.Elapsed, tried, totalCombinations, mhpsFinal);
    }
}
