using System.Text;

namespace CardHashDemo.Core;

public record BinEntry(string Prefix, string Issuer, int CardLength = 16);

public static class IsraeliCards
{
    public static readonly IReadOnlyList<BinEntry> KnownBins = new BinEntry[]
    {
        // ── Bank Hapoalim ─────────────────────────────────────────────────
        new("436201", "Bank Hapoalim Visa"),
        new("464100", "Bank Hapoalim Visa Platinum"),
        new("470640", "Bank Hapoalim Visa Gold"),
        new("532610", "Bank Hapoalim Mastercard"),
        new("375510", "Bank Hapoalim Amex", 15),
        new("375511", "Bank Hapoalim Amex Gold", 15),
        new("375512", "Bank Hapoalim Amex Platinum", 15),

        // ── Bank Leumi ────────────────────────────────────────────────────
        new("492840", "Bank Leumi Visa"),
        new("431195", "Bank Leumi Visa Classic"),
        new("458003", "Bank Leumi Visa"),
        new("458012", "Bank Leumi Visa"),
        new("406423", "Bank Leumi Visa"),
        new("407516", "Bank Leumi Visa"),
        new("407517", "Bank Leumi Visa Gold"),
        new("407518", "Bank Leumi Visa Platinum"),
        new("518955", "Bank Leumi Mastercard"),
        new("552176", "Bank Leumi Mastercard"),

        // ── Discount Bank ─────────────────────────────────────────────────
        new("479614", "Discount Bank Visa"),
        new("457946", "Discount Bank Visa Gold"),
        new("458008", "Discount Bank Visa"),
        new("458016", "Discount Bank Visa"),

        // ── Mizrahi-Tefahot ───────────────────────────────────────────────
        new("454030", "Mizrahi-Tefahot Visa"),
        new("458024", "Mizrahi-Tefahot Visa"),

        // ── First International Bank (Beinleumi / Union) ──────────────────
        new("458021", "Union Bank Visa"),
        new("458027", "Beinleumi Visa"),
        new("458036", "Beinleumi Visa"),

        // ── Aminit (Otsar Ha-Hayal Bank) ──────────────────────────────────
        new("431905", "Aminit Visa"),
        new("431906", "Aminit Visa"),
        new("431907", "Aminit Visa Business"),

        // ── Max / Israel Credit Cards Ltd. (Visa) ─────────────────────────
        new("458000", "Max Visa Classic"),
        new("458001", "Max Visa Classic"),
        new("458004", "Max Visa Classic"),
        new("458005", "Max Visa Classic"),
        new("458006", "Max Visa Classic"),
        new("458007", "Max Visa Classic"),
        new("458009", "Max Visa Classic"),
        new("458013", "Max Visa"),
        new("458017", "Max Visa"),
        new("458025", "Max Visa Gold"),
        new("458026", "Max Visa Gold"),
        new("458028", "Max Visa Gold"),
        new("458029", "Max Visa Gold"),
        new("458030", "Max Visa Corporate"),
        new("458031", "Max Visa Platinum"),
        new("458032", "Max Visa Corporate"),
        new("458039", "Max Visa Platinum"),
        new("458050", "Max Visa Platinum"),
        new("458057", "Max Visa Platinum"),
        new("458078", "Max Visa Platinum"),
        new("458079", "Max Visa Infinite"),
        new("458085", "Max Visa Infinite"),
        new("458091", "Max Visa Business"),
        new("458094", "Max Visa Business"),
        new("458095", "Max Visa Business"),
        new("458096", "Max Visa Business"),
        new("458097", "Max Visa Business"),
        new("458098", "Max Visa Business"),
        new("458099", "Max Visa Business"),

        // ── Max / Israel Credit Cards Ltd. (Mastercard) ───────────────────
        new("510046", "Max Mastercard"),
        new("518986", "Max Mastercard Gold"),
        new("518987", "Max Mastercard"),
        new("526568", "Max Mastercard"),
        new("527136", "Max Mastercard"),
        new("527141", "Max (CAL) Mastercard"),
        new("535840", "Max Mastercard Platinum"),
        new("536406", "Max Mastercard"),
        new("545136", "Max Mastercard World"),
        new("547707", "Max Mastercard Business"),
        new("552183", "Max Mastercard Platinum"),

        // ── Isracard Ltd. (Visa Debit) ────────────────────────────────────
        new("412551", "Isracard Visa Debit"),
        new("421910", "Isracard Visa Debit"),
        new("421911", "Isracard Visa Debit"),
        new("421914", "Isracard Visa Debit"),
        new("427776", "Isracard Visa Debit"),
        new("466787", "Isracard Visa Debit"),
        new("466788", "Isracard Visa Debit"),
        new("468509", "Isracard Visa Debit"),
        new("526586", "Isracard Mastercard"),

        // ── Isracard Ltd. (Mastercard) ────────────────────────────────────
        new("512020", "Isracard Mastercard"),
        new("519165", "Isracard Mastercard"),
        new("522377", "Isracard Mastercard"),
        new("528218", "Isracard Mastercard"),
        new("552035", "Isracard Mastercard Debit"),
        new("555475", "Isracard Mastercard"),
        new("555650", "Isracard Mastercard"),
        new("555824", "Isracard Mastercard Debit"),

        // ── American Express Israel (15 digits) ───────────────────────────
        new("376818", "American Express Israel", 15),

        // ── Diners Club Israel (14 digits) ────────────────────────────────
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
