using System.Security.Cryptography;
using System.Text;
using CardHashDemo.Core;
using NUnit.Framework;

namespace CardHashDemo.Tests;

[TestFixture]
public class HashCrackerTests
{
    // "4362010000000003" — BIN 436201, free digits 000000000 = index 0 → found immediately
    private const string KnownCard = "4362010000000003";
    private static readonly BinEntry HapoalimBin = new("436201", "Bank Hapoalim Visa");

    private static string Sha1Hex(string input) =>
        Convert.ToHexString(SHA1.HashData(Encoding.ASCII.GetBytes(input)));

    private static string Sha256Hex(string input) =>
        Convert.ToHexString(SHA256.HashData(Encoding.ASCII.GetBytes(input)));

    [Test]
    public async Task Crack_Sha1_NoSalt_FindsCardAtIndexZero()
    {
        var result = await HashCracker.CrackAsync(
            Sha1Hex(KnownCard), HapoalimBin, HashAlgorithmName.SHA1,
            SaltMode.None, null, null, default);

        Assert.That(result.Card, Is.EqualTo(KnownCard));
    }

    [Test]
    public async Task Crack_Sha256_NoSalt_FindsCard()
    {
        var result = await HashCracker.CrackAsync(
            Sha256Hex(KnownCard), HapoalimBin, HashAlgorithmName.SHA256,
            SaltMode.None, null, null, default);

        Assert.That(result.Card, Is.EqualTo(KnownCard));
    }

    [Test]
    public async Task Crack_Sha256_StaticSalt_FindsCard()
    {
        byte[] salt  = Encoding.UTF8.GetBytes("MySuperSecretPepper");
        byte[] input = [.. salt, .. Encoding.ASCII.GetBytes(KnownCard)];
        string hash  = Convert.ToHexString(SHA256.HashData(input));

        var result = await HashCracker.CrackAsync(
            hash, HapoalimBin, HashAlgorithmName.SHA256,
            SaltMode.Static, salt, null, default);

        Assert.That(result.Card, Is.EqualTo(KnownCard));
    }

    [Test]
    public async Task Crack_Sha256_PerCardSalt_FindsCard()
    {
        byte[] salt  = [0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
                        0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10];
        byte[] input = [.. salt, .. Encoding.ASCII.GetBytes(KnownCard)];
        string hash  = Convert.ToHexString(SHA256.HashData(input));

        var result = await HashCracker.CrackAsync(
            hash, HapoalimBin, HashAlgorithmName.SHA256,
            SaltMode.PerCard, salt, null, default);

        Assert.That(result.Card, Is.EqualTo(KnownCard));
    }

    [Test]
    public async Task Crack_ReturnsNullCard_WhenHashNotFound()
    {
        // cardLength=7, freeDigits=0 → only 1 candidate, won't match bogus hash
        var tinyBin = new BinEntry("436201", "Test", CardLength: 7);
        string bogusHash = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

        var result = await HashCracker.CrackAsync(
            bogusHash, tinyBin, HashAlgorithmName.SHA1,
            SaltMode.None, null, null, default);

        Assert.That(result.Card, Is.Null);
        Assert.That(result.Total, Is.EqualTo(1));
    }
}
