namespace CardHashDemo.Core;

public static class LuhnAlgorithm
{
    /// <summary>Validates a complete card number (including check digit).</summary>
    public static bool Validate(ReadOnlySpan<char> pan)
    {
        if (pan.Length < 2) return false;
        int sum = 0;
        bool doubleIt = false; // rightmost digit (check digit) is NOT doubled
        for (int i = pan.Length - 1; i >= 0; i--)
        {
            int d = pan[i] - '0';
            if ((uint)d > 9) return false;
            if (doubleIt) { d *= 2; if (d > 9) d -= 9; }
            sum += d;
            doubleIt = !doubleIt;
        }
        return sum % 10 == 0;
    }

    /// <summary>
    /// Computes the Luhn check digit for a partial card number as ASCII bytes.
    /// partialBytes must NOT include the check digit.
    /// From the rightmost partial digit going left, the first (rightmost) digit is doubled.
    /// </summary>
    public static int ComputeCheckDigit(ReadOnlySpan<byte> partialBytes)
    {
        int sum = 0;
        bool doubleIt = true; // rightmost partial digit IS doubled (it sits at position 1 once check digit appended)
        for (int i = partialBytes.Length - 1; i >= 0; i--)
        {
            int d = partialBytes[i] - '0';
            if (doubleIt) { d *= 2; if (d > 9) d -= 9; }
            sum += d;
            doubleIt = !doubleIt;
        }
        return (10 - sum % 10) % 10;
    }
}
