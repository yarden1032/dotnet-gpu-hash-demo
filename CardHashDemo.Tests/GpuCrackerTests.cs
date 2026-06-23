using System.Security.Cryptography;
using System.Text;
using CardHashDemo.Core;
using CardHashDemo.Gpu;
using NUnit.Framework;

namespace CardHashDemo.Tests;

[TestFixture]
[NonParallelizable]
public class GpuCrackerTests
{
    private const string KnownCard = "4362010000000003";
    private static readonly BinEntry HapoalimBin = new("436201", "Bank Hapoalim Visa");

    [Test]
    public void Crack_Sha1_NoSalt_FindsCardOnDetectedGpu()
    {
        var detected = GpuCracker.DetectGpu();
        if (detected is null)
            Assert.Ignore("No CUDA/OpenCL GPU was detected.");

        string hash = Convert.ToHexString(SHA1.HashData(Encoding.ASCII.GetBytes(KnownCard)));
        var result = GpuCracker.Crack(hash, HapoalimBin, useSha256: false, salt: [], detected.Value);

        Assert.That(result.Card, Is.EqualTo(KnownCard));
    }

    [Test]
    public void Crack_Sha256_NoSalt_FindsCardOnDetectedGpu()
    {
        var detected = GpuCracker.DetectGpu();
        if (detected is null)
            Assert.Ignore("No CUDA/OpenCL GPU was detected.");

        string hash = Convert.ToHexString(SHA256.HashData(Encoding.ASCII.GetBytes(KnownCard)));
        var result = GpuCracker.Crack(hash, HapoalimBin, useSha256: true, salt: [], detected.Value);

        Assert.That(result.Card, Is.EqualTo(KnownCard));
    }

    [Test]
    public void Crack_Sha256_WithSixteenByteSalt_FindsCardOnDetectedGpu()
    {
        var detected = GpuCracker.DetectGpu();
        if (detected is null)
            Assert.Ignore("No CUDA/OpenCL GPU was detected.");

        byte[] salt = Encoding.ASCII.GetBytes("Pepper16ByteKey!");
        byte[] input = [.. salt, .. Encoding.ASCII.GetBytes(KnownCard)];
        string hash = Convert.ToHexString(SHA256.HashData(input));

        var result = GpuCracker.Crack(hash, HapoalimBin, useSha256: true, salt, detected.Value);

        Assert.That(result.Card, Is.EqualTo(KnownCard));
    }
}
