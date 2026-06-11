using CardHashDemo.Core;
using NUnit.Framework;

namespace CardHashDemo.Tests;

[TestFixture]
public class IsraeliCardsTests
{
    [Test]
    public void KnownBins_HasAtLeast10Entries()
    {
        Assert.That(IsraeliCards.KnownBins.Count, Is.GreaterThanOrEqualTo(10));
    }

    [TestCase("4362010000000003", true)]   // Hapoalim prefix 436201
    [TestCase("5271360000000000", true)]   // Max prefix 527136
    [TestCase("4111111111111111", false)]  // not an Israeli BIN
    public void DetectIsraeli_KnownCards(string pan, bool expected)
    {
        var entry = IsraeliCards.DetectIsraeli(pan);
        Assert.That(entry is not null, Is.EqualTo(expected));
    }

    [Test]
    public void GenerateCard_ProducesValidLuhnCard()
    {
        var bin = IsraeliCards.KnownBins[0];
        string card = IsraeliCards.GenerateCard(bin);
        Assert.That(card.Length, Is.EqualTo(bin.CardLength));
        Assert.That(card, Does.StartWith(bin.Prefix));
        Assert.That(LuhnAlgorithm.Validate(card.AsSpan()), Is.True);
    }

    [Test]
    public void GenerateCard_DifferentCallsProduceDifferentCards()
    {
        var bin = IsraeliCards.KnownBins[0];
        var cards = Enumerable.Range(0, 20).Select(_ => IsraeliCards.GenerateCard(bin)).ToHashSet();
        Assert.That(cards.Count, Is.GreaterThan(1));
    }
}
