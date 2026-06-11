using System.Text;

namespace CardHashDemo.Core;

public record BinEntry(string Prefix, string Issuer, int CardLength = 16);

public static class IsraeliCards
{
    public static readonly IReadOnlyList<BinEntry> KnownBins = new BinEntry[]
    {
        // Bank Hapoalim
        new("436201", "Bank Hapoalim Visa"),
        new("464100", "Bank Hapoalim Visa Platinum"),
        new("470640", "Bank Hapoalim Visa Gold"),
        // Bank Leumi
        new("492840", "Bank Leumi Visa"),
        new("431195", "Bank Leumi Visa Classic"),
        new("458003", "Bank Leumi Visa"),
        // Discount Bank
        new("479614", "Discount Bank Visa"),
        new("457946", "Discount Bank Visa Gold"),
        // Mizrahi-Tefahot
        new("454030", "Mizrahi-Tefahot Visa"),
        new("458024", "Mizrahi-Tefahot Visa"),
        // First International / Union / Beinleumi
        new("458021", "Union Bank Visa"),
        new("458036", "Beinleumi (First International) Visa"),
        // Max (Israel Credit Cards Ltd. — formerly Leumi Card / CAL)
        new("458028", "Max Visa"),
        new("458050", "Max Visa Platinum"),
        new("458079", "Max Visa Infinite"),
        new("527136", "Max (Leumi Card) Mastercard"),
        new("526568", "Max Mastercard"),
        new("535840", "Max Mastercard Platinum"),
        new("527141", "CAL Mastercard"),
        new("526586", "Isracard Mastercard"),
        // American Express Israel (15 digits)
        new("376818", "American Express Israel", 15),
        // Diners Club Israel (14 digits)
        new("304920", "Diners Club Israel", 14),
    };

    public static BinEntry? DetectIsraeli(string pan)
    {
        foreach (var entry in KnownBins)
            if (pan.StartsWith(entry.Prefix, StringComparison.Ordinal))
                return entry;
        return null;
    }

    /// <summary>Generates a random card number with a valid Luhn check digit for the given BIN.</summary>
    public static string GenerateCard(BinEntry bin)
    {
        int freeDigits = bin.CardLength - bin.Prefix.Length - 1;
        var sb = new StringBuilder(bin.CardLength);
        sb.Append(bin.Prefix);
        for (int i = 0; i < freeDigits; i++)
            sb.Append((char)('0' + Random.Shared.Next(10)));
        byte[] partial = Encoding.ASCII.GetBytes(sb.ToString());
        sb.Append((char)('0' + LuhnAlgorithm.ComputeCheckDigit(partial)));
        return sb.ToString();
    }
}
