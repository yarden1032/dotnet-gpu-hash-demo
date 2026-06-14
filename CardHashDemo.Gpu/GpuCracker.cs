using System.Text;
using CardHashDemo.Core;
using ILGPU;
using ILGPU.Runtime;
using ILGPU.Runtime.Cuda;
using ILGPU.Runtime.OpenCL;

namespace CardHashDemo.Gpu;

public enum GpuBackend { Cuda, OpenCL }

public record GpuCrackResult(string? Card, TimeSpan Elapsed, long Tried, long Total, double GHashSec);

public static class GpuCracker
{
    private const int BatchSize = 1 << 24; // 16 M candidates per GPU launch

    /// <summary>
    /// Detects the best available GPU backend: CUDA first, then OpenCL.
    /// Each backend gets its own isolated Context so a broken OpenCL driver
    /// (e.g. Intel Iris) cannot crash the whole detection.
    /// Returns null if no GPU is available.
    /// </summary>
    public static (GpuBackend Backend, string DeviceInfo)? DetectGpu()
    {
        // ── Try CUDA ──────────────────────────────────────────────────────
        try
        {
            using var ctx = Context.Create(b => b.Cuda());
            using var acc = ctx.CreateCudaAccelerator(0);
            return (GpuBackend.Cuda, $"{acc.Name}  ({acc.MemorySize / 1024 / 1024} MB VRAM)  [CUDA]");
        }
        catch { }

        // ── Try OpenCL ────────────────────────────────────────────────────
        try
        {
            using var ctx = Context.Create(b => b.OpenCL());
            using var acc = ctx.CreateCLAccelerator(0);
            return (GpuBackend.OpenCL, $"{acc.Name}  ({acc.MemorySize / 1024 / 1024} MB VRAM)  [OpenCL]");
        }
        catch { }

        return null;
    }

    public static GpuCrackResult Crack(
        string targetHashHex,
        BinEntry bin,
        bool useSha256,
        byte[] salt,
        GpuBackend backend,
        IProgress<(long tried, long total, TimeSpan elapsed)>? progress = null)
    {
        int freeDigits = bin.CardLength - bin.Prefix.Length - 1;
        long total = 1;
        for (int i = 0; i < freeDigits; i++) total *= 10;

        byte[] targetHash = Convert.FromHexString(targetHashHex);
        byte[] binBytes   = Encoding.ASCII.GetBytes(bin.Prefix);
        int    saltLength = salt.Length;

        using var context     = backend == GpuBackend.Cuda
            ? Context.Create(b => b.Cuda())
            : Context.Create(b => b.OpenCL());
        using var accelerator = backend == GpuBackend.Cuda
            ? (Accelerator)context.CreateCudaAccelerator(0)
            : context.CreateCLAccelerator(0);

        using var dBin       = accelerator.Allocate1D(binBytes);
        using var dTarget    = accelerator.Allocate1D(targetHash);
        // salt buffer: at least 1 byte to avoid zero-length allocation
        using var dSalt      = accelerator.Allocate1D(saltLength > 0 ? salt : new byte[1]);
        using var dFound     = accelerator.Allocate1D<long>(1);
        using var dFoundCard = accelerator.Allocate1D<byte>(bin.CardLength);

        dFound.CopyFromCPU([-1L]);

        var kernel = accelerator.LoadAutoGroupedStreamKernel<
            Index1D,
            long,
            long,
            ArrayView1D<byte, Stride1D.Dense>,
            int,
            int,
            int,
            ArrayView1D<byte, Stride1D.Dense>,
            int,
            bool,
            int,
            ArrayView1D<byte, Stride1D.Dense>,
            ArrayView1D<long, Stride1D.Dense>,
            ArrayView1D<byte, Stride1D.Dense>
        >(CrackKernel);

        var sw    = System.Diagnostics.Stopwatch.StartNew();
        long tried = 0;
        string? foundCard = null;

        for (long offset = 0; offset < total; offset += BatchSize)
        {
            long batchLen = Math.Min(BatchSize, total - offset);
            kernel(
                (int)batchLen,
                offset, total,
                dBin.View, bin.Prefix.Length, bin.CardLength, freeDigits,
                dTarget.View, targetHash.Length, useSha256,
                saltLength, dSalt.View,
                dFound.View, dFoundCard.View);
            accelerator.Synchronize();
            tried += batchLen;

            long[] foundBuf = new long[1];
            dFound.CopyToCPU(foundBuf);
            if (foundBuf[0] >= 0)
            {
                byte[] cardBuf = new byte[bin.CardLength];
                dFoundCard.CopyToCPU(cardBuf);
                foundCard = Encoding.ASCII.GetString(cardBuf);
                break;
            }

            progress?.Report((tried, total, sw.Elapsed));
        }

        sw.Stop();
        double ghps = sw.Elapsed.TotalSeconds > 0 ? tried / sw.Elapsed.TotalSeconds / 1_000_000_000.0 : 0;
        return new GpuCrackResult(foundCard, sw.Elapsed, tried, total, ghps);
    }

    // ── ILGPU kernel ──────────────────────────────────────────────────────

    private static void CrackKernel(
        Index1D index,
        long batchOffset,
        long totalCombinations,
        ArrayView1D<byte, Stride1D.Dense> bin,
        int binLen,
        int cardLength,
        int freeDigits,
        ArrayView1D<byte, Stride1D.Dense> targetHash,
        int hashLen,
        bool useSha256,
        int saltLength,
        ArrayView1D<byte, Stride1D.Dense> salt,
        ArrayView1D<long, Stride1D.Dense> foundIndex,
        ArrayView1D<byte, Stride1D.Dense> foundCard)
    {
        long candidateIdx = batchOffset + index.X;
        if (candidateIdx >= totalCombinations || foundIndex[0] >= 0) return;

        // ── Build card bytes (6 BIN + 9 free + 1 Luhn = 16) ──────────────
        byte b0=bin[0], b1=bin[1], b2=bin[2], b3=bin[3], b4=bin[4], b5=bin[5];

        long val = candidateIdx;
        byte d14=(byte)('0'+val%10); val/=10;
        byte d13=(byte)('0'+val%10); val/=10;
        byte d12=(byte)('0'+val%10); val/=10;
        byte d11=(byte)('0'+val%10); val/=10;
        byte d10=(byte)('0'+val%10); val/=10;
        byte d09=(byte)('0'+val%10); val/=10;
        byte d08=(byte)('0'+val%10); val/=10;
        byte d07=(byte)('0'+val%10); val/=10;
        byte d06=(byte)('0'+val%10);

        // ── Luhn check digit ──────────────────────────────────────────────
        // From rightmost partial digit (d14) going left, double every other starting at d14
        static int DD(byte b, bool dbl) { int v=b-48; if(dbl){v*=2;if(v>9)v-=9;} return v; }
        int s = DD(d14,true) +DD(d13,false)+DD(d12,true) +DD(d11,false)+DD(d10,true)
              + DD(d09,false)+DD(d08,true) +DD(d07,false)+DD(d06,true)
              + DD(b5,false) +DD(b4,true)  +DD(b3,false) +DD(b2,true)
              + DD(b1,false) +DD(b0,true);
        byte d15 = (byte)('0' + (10 - s % 10) % 10);

        // ── Pack padded block: salt(0 or 16 bytes) || card(16 bytes) ──────
        uint pm0,pm1,pm2,pm3,pm4,pm5,pm6,pm7,pm8,pm9,pm10,pm11,pm12,pm13,pm14,pm15;
        pm9=pm10=pm11=pm12=pm13=0;

        if (saltLength == 0)
        {
            // 16-byte card → fits in W[0..3], padding at W[4], length=128 in W[15]
            pm0 = ((uint)b0 <<24)|((uint)b1 <<16)|((uint)b2 <<8)|b3;
            pm1 = ((uint)b4 <<24)|((uint)b5 <<16)|((uint)d06<<8)|d07;
            pm2 = ((uint)d08<<24)|((uint)d09<<16)|((uint)d10<<8)|d11;
            pm3 = ((uint)d12<<24)|((uint)d13<<16)|((uint)d14<<8)|d15;
            pm4 = 0x80000000u;
            pm5=pm6=pm7=pm8=0;
            pm14=0; pm15=128u;
        }
        else // saltLength == 16
        {
            // 16-byte salt || 16-byte card = 32 bytes → W[0..7], padding W[8], length=256 in W[15]
            pm0 = ((uint)salt[0]<<24)|((uint)salt[1]<<16)|((uint)salt[2]<<8)|salt[3];
            pm1 = ((uint)salt[4]<<24)|((uint)salt[5]<<16)|((uint)salt[6]<<8)|salt[7];
            pm2 = ((uint)salt[8]<<24)|((uint)salt[9]<<16)|((uint)salt[10]<<8)|salt[11];
            pm3 = ((uint)salt[12]<<24)|((uint)salt[13]<<16)|((uint)salt[14]<<8)|salt[15];
            pm4 = ((uint)b0<<24)|((uint)b1<<16)|((uint)b2<<8)|b3;
            pm5 = ((uint)b4<<24)|((uint)b5<<16)|((uint)d06<<8)|d07;
            pm6 = ((uint)d08<<24)|((uint)d09<<16)|((uint)d10<<8)|d11;
            pm7 = ((uint)d12<<24)|((uint)d13<<16)|((uint)d14<<8)|d15;
            pm8 = 0x80000000u;
            pm14=0; pm15=256u;
        }

        // ── Hash and compare ──────────────────────────────────────────────
        bool match;
        if (!useSha256)
        {
            GpuHash.Sha1(pm0,pm1,pm2,pm3,pm4,pm5,pm6,pm7,pm8,pm9,pm10,pm11,pm12,pm13,pm14,pm15,
                out uint h0,out uint h1,out uint h2,out uint h3,out uint h4);
            match =
                targetHash[0]==(byte)(h0>>24) && targetHash[1]==(byte)(h0>>16) &&
                targetHash[2]==(byte)(h0>> 8) && targetHash[3]==(byte) h0      &&
                targetHash[4]==(byte)(h1>>24) && targetHash[5]==(byte)(h1>>16) &&
                targetHash[6]==(byte)(h1>> 8) && targetHash[7]==(byte) h1      &&
                targetHash[8]==(byte)(h2>>24) && targetHash[9]==(byte)(h2>>16) &&
                targetHash[10]==(byte)(h2>>8) && targetHash[11]==(byte)h2      &&
                targetHash[12]==(byte)(h3>>24)&& targetHash[13]==(byte)(h3>>16)&&
                targetHash[14]==(byte)(h3>>8) && targetHash[15]==(byte)h3      &&
                targetHash[16]==(byte)(h4>>24)&& targetHash[17]==(byte)(h4>>16)&&
                targetHash[18]==(byte)(h4>>8) && targetHash[19]==(byte)h4;
        }
        else
        {
            GpuHash.Sha256(pm0,pm1,pm2,pm3,pm4,pm5,pm6,pm7,pm8,pm9,pm10,pm11,pm12,pm13,pm14,pm15,
                out uint h0,out uint h1,out uint h2,out uint h3,
                out uint h4,out uint h5,out uint h6,out uint h7);
            match =
                targetHash[0]==(byte)(h0>>24) && targetHash[1]==(byte)(h0>>16) &&
                targetHash[2]==(byte)(h0>> 8) && targetHash[3]==(byte) h0      &&
                targetHash[4]==(byte)(h1>>24) && targetHash[5]==(byte)(h1>>16) &&
                targetHash[6]==(byte)(h1>> 8) && targetHash[7]==(byte) h1      &&
                targetHash[8]==(byte)(h2>>24) && targetHash[9]==(byte)(h2>>16) &&
                targetHash[10]==(byte)(h2>>8) && targetHash[11]==(byte)h2      &&
                targetHash[12]==(byte)(h3>>24)&& targetHash[13]==(byte)(h3>>16)&&
                targetHash[14]==(byte)(h3>>8) && targetHash[15]==(byte)h3      &&
                targetHash[16]==(byte)(h4>>24)&& targetHash[17]==(byte)(h4>>16)&&
                targetHash[18]==(byte)(h4>>8) && targetHash[19]==(byte)h4      &&
                targetHash[20]==(byte)(h5>>24)&& targetHash[21]==(byte)(h5>>16)&&
                targetHash[22]==(byte)(h5>>8) && targetHash[23]==(byte)h5      &&
                targetHash[24]==(byte)(h6>>24)&& targetHash[25]==(byte)(h6>>16)&&
                targetHash[26]==(byte)(h6>>8) && targetHash[27]==(byte)h6      &&
                targetHash[28]==(byte)(h7>>24)&& targetHash[29]==(byte)(h7>>16)&&
                targetHash[30]==(byte)(h7>>8) && targetHash[31]==(byte)h7;
        }

        if (match && Atomic.CompareExchange(ref foundIndex[0], candidateIdx, -1L) == -1L)
        {
            foundCard[0]=b0;  foundCard[1]=b1;  foundCard[2]=b2;  foundCard[3]=b3;
            foundCard[4]=b4;  foundCard[5]=b5;  foundCard[6]=d06; foundCard[7]=d07;
            foundCard[8]=d08; foundCard[9]=d09; foundCard[10]=d10;foundCard[11]=d11;
            foundCard[12]=d12;foundCard[13]=d13;foundCard[14]=d14;foundCard[15]=d15;
        }
    }
}
