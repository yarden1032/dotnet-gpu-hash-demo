// ═══════════════════════════════════════════════════════════════════════════
// WHY DOES THIS FILE LOOK SO LOW-LEVEL?
//
// ILGPU compiles C# directly to GPU machine code (PTX for CUDA, SPIR-V for
// OpenCL). Inside a GPU kernel there is no runtime, no GC, and no heap.
// That means the following normal C# patterns are ALL ILLEGAL in kernel code:
//
//   uint[] w = new uint[16]      — no heap, 'new' doesn't exist
//   static readonly uint[] K256  — static arrays live on the CPU heap
//   Span<T> / stackalloc         — CPU stack concept, GPU threads lack it
//   List<T>, LINQ                — require heap allocation
//   interfaces / abstract        — require a vtable (virtual dispatch)
//
// Consequences visible in this file:
//
//   W16 struct   — 16 named uint fields (_0.._15) instead of uint[16].
//                  The switch-based Get/Set compiles to direct register access,
//                  which is exactly what a small fixed array would do anyway.
//
//   K256 method  — 64-case switch instead of a lookup array, same reason.
//
//   All uint math — no library support inside kernels; everything is manual.
//
// This is not a C# limitation — CUDA C++ and OpenCL C have the same rules.
// ILGPU just lets you write GPU code in C# syntax instead of a separate file.
// ═══════════════════════════════════════════════════════════════════════════

namespace CardHashDemo.Core;

/// <summary>
/// 16-element circular buffer for the SHA message schedule W[0..79].
/// Only value-type fields — safe inside ILGPU GPU kernels (no heap allocation).
/// </summary>
public struct W16
{
    private uint _0,_1,_2,_3,_4,_5,_6,_7,_8,_9,_10,_11,_12,_13,_14,_15;

    public void Set(int i, uint v)
    {
        switch (i & 15)
        {
            case  0: _0 =v; break; case  1: _1 =v; break; case  2: _2 =v; break; case  3: _3 =v; break;
            case  4: _4 =v; break; case  5: _5 =v; break; case  6: _6 =v; break; case  7: _7 =v; break;
            case  8: _8 =v; break; case  9: _9 =v; break; case 10: _10=v; break; case 11: _11=v; break;
            case 12: _12=v; break; case 13: _13=v; break; case 14: _14=v; break; default:  _15=v; break;
        }
    }

    public uint Get(int i) => (i & 15) switch
    {
        0=>_0, 1=>_1, 2=>_2, 3=>_3, 4=>_4, 5=>_5, 6=>_6, 7=>_7,
        8=>_8, 9=>_9, 10=>_10, 11=>_11, 12=>_12, 13=>_13, 14=>_14, _=>_15
    };

    public void Expand(int round) // round >= 16
    {
        uint v = Get(round-3) ^ Get(round-8) ^ Get(round-14) ^ Get(round-16);
        Set(round, (v << 1) | (v >> 31)); // ROTL1
    }
}

/// <summary>
/// SHA1 and SHA256 implemented as pure arithmetic — compatible with ILGPU GPU kernels.
/// No heap allocation, no virtual dispatch, value types only.
/// </summary>
public static class GpuHash
{
    // ── SHA1 ──────────────────────────────────────────────────────────────

    private static void Sha1Block(ref W16 w,
        out uint h0, out uint h1, out uint h2, out uint h3, out uint h4)
    {
        const uint A0=0x67452301u, B0=0xEFCDAB89u, C0=0x98BADCFEu, D0=0x10325476u, E0=0xC3D2E1F0u;
        uint a=A0, b=B0, c=C0, d=D0, e=E0;

        for (int t = 0; t < 80; t++)
        {
            if (t >= 16) w.Expand(t);
            uint wt = w.Get(t);
            uint f, k;
            if      (t < 20) { f = (b & c) | (~b & d);         k = 0x5A827999u; }
            else if (t < 40) { f = b ^ c ^ d;                  k = 0x6ED9EBA1u; }
            else if (t < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDCu; }
            else             { f = b ^ c ^ d;                  k = 0xCA62C1D6u; }
            uint temp = ((a << 5) | (a >> 27)) + f + e + k + wt;
            e=d; d=c; c=(b << 30)|(b >> 2); b=a; a=temp;
        }
        h0=A0+a; h1=B0+b; h2=C0+c; h3=D0+d; h4=E0+e;
    }

    /// <summary>SHA1 of one 512-bit padded block (16 big-endian words).</summary>
    public static void Sha1(
        uint m0,  uint m1,  uint m2,  uint m3,  uint m4,  uint m5,  uint m6,  uint m7,
        uint m8,  uint m9,  uint m10, uint m11, uint m12, uint m13, uint m14, uint m15,
        out uint h0, out uint h1, out uint h2, out uint h3, out uint h4)
    {
        var w = new W16();
        w.Set(0,m0);  w.Set(1,m1);  w.Set(2,m2);   w.Set(3,m3);
        w.Set(4,m4);  w.Set(5,m5);  w.Set(6,m6);   w.Set(7,m7);
        w.Set(8,m8);  w.Set(9,m9);  w.Set(10,m10); w.Set(11,m11);
        w.Set(12,m12); w.Set(13,m13); w.Set(14,m14); w.Set(15,m15);
        Sha1Block(ref w, out h0, out h1, out h2, out h3, out h4);
    }

    // ── SHA256 ────────────────────────────────────────────────────────────

    // Switch-based constant table — ILGPU cannot use static readonly arrays in GPU kernels.
    private static uint K256(int t) => t switch {
        0  => 0x428a2f98u, 1  => 0x71374491u, 2  => 0xb5c0fbcfu, 3  => 0xe9b5dba5u,
        4  => 0x3956c25bu, 5  => 0x59f111f1u, 6  => 0x923f82a4u, 7  => 0xab1c5ed5u,
        8  => 0xd807aa98u, 9  => 0x12835b01u, 10 => 0x243185beu, 11 => 0x550c7dc3u,
        12 => 0x72be5d74u, 13 => 0x80deb1feu, 14 => 0x9bdc06a7u, 15 => 0xc19bf174u,
        16 => 0xe49b69c1u, 17 => 0xefbe4786u, 18 => 0x0fc19dc6u, 19 => 0x240ca1ccu,
        20 => 0x2de92c6fu, 21 => 0x4a7484aau, 22 => 0x5cb0a9dcu, 23 => 0x76f988dau,
        24 => 0x983e5152u, 25 => 0xa831c66du, 26 => 0xb00327c8u, 27 => 0xbf597fc7u,
        28 => 0xc6e00bf3u, 29 => 0xd5a79147u, 30 => 0x06ca6351u, 31 => 0x14292967u,
        32 => 0x27b70a85u, 33 => 0x2e1b2138u, 34 => 0x4d2c6dfcu, 35 => 0x53380d13u,
        36 => 0x650a7354u, 37 => 0x766a0abbu, 38 => 0x81c2c92eu, 39 => 0x92722c85u,
        40 => 0xa2bfe8a1u, 41 => 0xa81a664bu, 42 => 0xc24b8b70u, 43 => 0xc76c51a3u,
        44 => 0xd192e819u, 45 => 0xd6990624u, 46 => 0xf40e3585u, 47 => 0x106aa070u,
        48 => 0x19a4c116u, 49 => 0x1e376c08u, 50 => 0x2748774cu, 51 => 0x34b0bcb5u,
        52 => 0x391c0cb3u, 53 => 0x4ed8aa4au, 54 => 0x5b9cca4fu, 55 => 0x682e6ff3u,
        56 => 0x748f82eeu, 57 => 0x78a5636fu, 58 => 0x84c87814u, 59 => 0x8cc70208u,
        60 => 0x90befffau, 61 => 0xa4506cebu, 62 => 0xbef9a3f7u, _ => 0xc67178f2u
    };

    private static void Sha256Block(ref W16 w,
        out uint h0, out uint h1, out uint h2, out uint h3,
        out uint h4, out uint h5, out uint h6, out uint h7)
    {
        const uint A0=0x6a09e667u, B0=0xbb67ae85u, C0=0x3c6ef372u, D0=0xa54ff53au;
        const uint E0=0x510e527fu, F0=0x9b05688cu, G0=0x1f83d9abu, H0v=0x5be0cd19u;
        uint a=A0, b=B0, c=C0, d=D0, e=E0, f=F0, g=G0, h=H0v;

        for (int t = 0; t < 64; t++)
        {
            if (t >= 16)
            {
                uint wt2  = w.Get(t-2);
                uint wt7  = w.Get(t-7);
                uint wt15 = w.Get(t-15);
                uint wt16 = w.Get(t-16);
                uint s1 = ((wt2  >> 17) | (wt2  << 15)) ^ ((wt2  >> 19) | (wt2  << 13)) ^ (wt2  >> 10);
                uint s0 = ((wt15 >>  7) | (wt15 << 25)) ^ ((wt15 >> 18) | (wt15 << 14)) ^ (wt15 >>  3);
                w.Set(t, s1 + wt7 + s0 + wt16);
            }
            uint wt_   = w.Get(t);
            uint S1    = ((e >> 6)|(e << 26)) ^ ((e >> 11)|(e << 21)) ^ ((e >> 25)|(e <<  7));
            uint ch    = (e & f) ^ (~e & g);
            uint temp1 = h + S1 + ch + K256(t) + wt_;
            uint S0    = ((a >> 2)|(a << 30)) ^ ((a >> 13)|(a << 19)) ^ ((a >> 22)|(a << 10));
            uint maj   = (a & b) ^ (a & c) ^ (b & c);
            uint temp2 = S0 + maj;
            h=g; g=f; f=e; e=d+temp1; d=c; c=b; b=a; a=temp1+temp2;
        }
        h0=A0+a; h1=B0+b; h2=C0+c; h3=D0+d; h4=E0+e; h5=F0+f; h6=G0+g; h7=H0v+h;
    }

    /// <summary>SHA256 of one 512-bit padded block (16 big-endian words).</summary>
    public static void Sha256(
        uint m0,  uint m1,  uint m2,  uint m3,  uint m4,  uint m5,  uint m6,  uint m7,
        uint m8,  uint m9,  uint m10, uint m11, uint m12, uint m13, uint m14, uint m15,
        out uint h0, out uint h1, out uint h2, out uint h3,
        out uint h4, out uint h5, out uint h6, out uint h7)
    {
        var w = new W16();
        w.Set(0,m0);  w.Set(1,m1);  w.Set(2,m2);   w.Set(3,m3);
        w.Set(4,m4);  w.Set(5,m5);  w.Set(6,m6);   w.Set(7,m7);
        w.Set(8,m8);  w.Set(9,m9);  w.Set(10,m10); w.Set(11,m11);
        w.Set(12,m12); w.Set(13,m13); w.Set(14,m14); w.Set(15,m15);
        Sha256Block(ref w, out h0, out h1, out h2, out h3, out h4, out h5, out h6, out h7);
    }

    // ── Shared helper ─────────────────────────────────────────────────────

    /// <summary>
    /// Packs inputBytes (length inputLen, max 55 bytes) into 16 big-endian 32-bit words
    /// of a single padded 512-bit block for SHA1 or SHA256.
    /// </summary>
    public static void BuildPaddedBlock(
        ReadOnlySpan<byte> inputBytes, int inputLen,
        out uint m0,  out uint m1,  out uint m2,  out uint m3,
        out uint m4,  out uint m5,  out uint m6,  out uint m7,
        out uint m8,  out uint m9,  out uint m10, out uint m11,
        out uint m12, out uint m13, out uint m14, out uint m15)
    {
        Span<byte> block = stackalloc byte[64];
        block.Clear();
        inputBytes[..inputLen].CopyTo(block);
        block[inputLen] = 0x80;
        ulong bitLen = (ulong)inputLen * 8;
        block[56] = (byte)(bitLen >> 56); block[57] = (byte)(bitLen >> 48);
        block[58] = (byte)(bitLen >> 40); block[59] = (byte)(bitLen >> 32);
        block[60] = (byte)(bitLen >> 24); block[61] = (byte)(bitLen >> 16);
        block[62] = (byte)(bitLen >>  8); block[63] = (byte) bitLen;

        static uint BE(ReadOnlySpan<byte> b, int i) =>
            ((uint)b[i] << 24) | ((uint)b[i+1] << 16) | ((uint)b[i+2] << 8) | b[i+3];

        m0 =BE(block, 0);  m1 =BE(block, 4);  m2 =BE(block, 8);  m3 =BE(block,12);
        m4 =BE(block,16);  m5 =BE(block,20);  m6 =BE(block,24);  m7 =BE(block,28);
        m8 =BE(block,32);  m9 =BE(block,36);  m10=BE(block,40);  m11=BE(block,44);
        m12=BE(block,48);  m13=BE(block,52);  m14=BE(block,56);  m15=BE(block,60);
    }
}
