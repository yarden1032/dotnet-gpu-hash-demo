using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using CardHashDemo.Core;
using NUnit.Framework;

namespace CardHashDemo.Tests;

[TestFixture]
public class GpuHashTests
{
    private static (byte[] block, int len) MakeBlock(string ascii)
    {
        byte[] bytes = Encoding.ASCII.GetBytes(ascii);
        GpuHash.BuildPaddedBlock(bytes, bytes.Length,
            out var m0,  out var m1,  out var m2,  out var m3,
            out var m4,  out var m5,  out var m6,  out var m7,
            out var m8,  out var m9,  out var m10, out var m11,
            out var m12, out var m13, out var m14, out var m15);

        // Pack back to byte array so we can pass as a single arg
        Span<byte> buf = stackalloc byte[64];
        BinaryPrimitives.WriteUInt32BigEndian(buf,      m0);
        BinaryPrimitives.WriteUInt32BigEndian(buf[4..], m1);
        BinaryPrimitives.WriteUInt32BigEndian(buf[8..], m2);
        BinaryPrimitives.WriteUInt32BigEndian(buf[12..],m3);
        // just return the original words via a helper tuple
        return (bytes, bytes.Length);
    }

    private static byte[] RunSha1(string ascii)
    {
        byte[] input = Encoding.ASCII.GetBytes(ascii);
        GpuHash.BuildPaddedBlock(input, input.Length,
            out var m0,  out var m1,  out var m2,  out var m3,
            out var m4,  out var m5,  out var m6,  out var m7,
            out var m8,  out var m9,  out var m10, out var m11,
            out var m12, out var m13, out var m14, out var m15);

        GpuHash.Sha1(m0,m1,m2,m3,m4,m5,m6,m7,m8,m9,m10,m11,m12,m13,m14,m15,
            out var h0, out var h1, out var h2, out var h3, out var h4);

        byte[] result = new byte[20];
        BinaryPrimitives.WriteUInt32BigEndian(result,       h0);
        BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(4),  h1);
        BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(8),  h2);
        BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(12), h3);
        BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(16), h4);
        return result;
    }

    private static byte[] RunSha256(string ascii)
    {
        byte[] input = Encoding.ASCII.GetBytes(ascii);
        GpuHash.BuildPaddedBlock(input, input.Length,
            out var m0,  out var m1,  out var m2,  out var m3,
            out var m4,  out var m5,  out var m6,  out var m7,
            out var m8,  out var m9,  out var m10, out var m11,
            out var m12, out var m13, out var m14, out var m15);

        GpuHash.Sha256(m0,m1,m2,m3,m4,m5,m6,m7,m8,m9,m10,m11,m12,m13,m14,m15,
            out var h0, out var h1, out var h2, out var h3,
            out var h4, out var h5, out var h6, out var h7);

        byte[] result = new byte[32];
        BinaryPrimitives.WriteUInt32BigEndian(result,        h0);
        BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(4),  h1);
        BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(8),  h2);
        BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(12), h3);
        BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(16), h4);
        BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(20), h5);
        BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(24), h6);
        BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(28), h7);
        return result;
    }

    [TestCase("4362010000000003")]   // Hapoalim test card at index 0
    [TestCase("4111111111111111")]   // classic Visa test card
    [TestCase("abc")]
    public void Sha1_MatchesDotNet(string input)
    {
        byte[] expected = SHA1.HashData(Encoding.ASCII.GetBytes(input));
        byte[] actual   = RunSha1(input);
        Assert.That(actual, Is.EqualTo(expected));
    }

    [TestCase("4362010000000003")]
    [TestCase("4111111111111111")]
    [TestCase("abc")]
    public void Sha256_MatchesDotNet(string input)
    {
        byte[] expected = SHA256.HashData(Encoding.ASCII.GetBytes(input));
        byte[] actual   = RunSha256(input);
        Assert.That(actual, Is.EqualTo(expected));
    }
}
