using CardHashDemo.Core;
using NUnit.Framework;

namespace CardHashDemo.Tests;

[TestFixture]
public class ResultSummaryTests
{
    [Test]
    public void Write_IncludesNoBinKnownEstimates()
    {
        var summary = new ResultSummary
        {
            MachineType = "CPU",
            HardwareInfo = "test hardware",
            RunAt = new DateTime(2026, 6, 25, 12, 0, 0),
            Card = "4362010000000003",
            BinPrefix = "436201",
            BinIssuer = "Bank Hapoalim Visa",
            Attacks =
            [
                new AttackResult(
                    "SHA1  (no salt)",
                    TimeSpan.FromSeconds(1),
                    HashesPerSecond: 1000.0,
                    Tried: 1,
                    Total: 1)
            ],
        };

        string path = summary.Write();
        try
        {
            string text = File.ReadAllText(path);

            Assert.That(text, Does.Contain("[No BIN Known Estimated Crack Times]"));
            Assert.That(text, Does.Contain("10,000,000x larger than one known BIN"));
            Assert.That(text, Does.Contain("Space (PAN only, no BIN)"));
            Assert.That(text, Does.Contain("Space (full Track2, no BIN)"));
        }
        finally
        {
            File.Delete(path);
        }
    }
}
