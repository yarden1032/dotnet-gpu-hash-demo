using System.Text;
using CardHashDemo.Core;
using NUnit.Framework;

namespace CardHashDemo.Tests;

[TestFixture]
public class LuhnAlgorithmTests
{
    [TestCase("4111111111111111", true)]   // standard Visa test card
    [TestCase("4362010000000003", true)]   // Hapoalim BIN, free digits=000000000
    [TestCase("4362010000000004", false)]  // one check digit off
    [TestCase("1234567890123452", true)]   // generic valid Luhn
    [TestCase("1234567890123451", false)]  // invalid
    public void Validate_KnownCards(string pan, bool expected)
    {
        bool result = LuhnAlgorithm.Validate(pan.AsSpan());
        Assert.That(result, Is.EqualTo(expected));
    }

    [Test]
    public void ComputeCheckDigit_Hapoalim_IndexZero()
    {
        // "436201000000000" (15 digits) → check digit must be 3
        byte[] partial = Encoding.ASCII.GetBytes("436201000000000");
        int checkDigit = LuhnAlgorithm.ComputeCheckDigit(partial);
        Assert.That(checkDigit, Is.EqualTo(3));
    }

    [Test]
    public void ComputeCheckDigit_VisaTest()
    {
        // "411111111111111" → check digit must be 1
        byte[] partial = Encoding.ASCII.GetBytes("411111111111111");
        int checkDigit = LuhnAlgorithm.ComputeCheckDigit(partial);
        Assert.That(checkDigit, Is.EqualTo(1));
    }

    [Test]
    public void RoundTrip_GeneratedCard_AlwaysValid()
    {
        byte[] partial = Encoding.ASCII.GetBytes("527136123456789");
        int cd = LuhnAlgorithm.ComputeCheckDigit(partial);
        string full = "527136123456789" + cd;
        Assert.That(LuhnAlgorithm.Validate(full.AsSpan()), Is.True);
    }
}
