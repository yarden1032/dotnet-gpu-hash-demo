using System.Text;
using CardHashDemo.Core;
using ILGPU;
using ILGPU.Runtime;
using ILGPU.Runtime.Cuda;
using ILGPU.Runtime.OpenCL;

namespace CardHashDemo.Gpu;

public enum GpuBackend { Cuda, OpenCL }

public readonly record struct GpuDeviceOption(GpuBackend Backend, int DeviceIndex, string DeviceInfo);

public readonly record struct GpuDetectionIssue(
    GpuBackend Backend,
    int DeviceIndex,
    string DeviceInfo,
    string Reason);

public record GpuCrackResult(string? Card, TimeSpan Elapsed, long Tried, long Total, double GHashSec);

public static class GpuCracker
{
    // Each kernel launch checks this many candidate PAN bodies.
    //
    // The full search space for one 16-digit BIN is 10^9 candidates, which is
    // larger than the practical size of one launch and too large for an int
    // length parameter. Splitting the work into batches keeps every launch
    // small enough while still giving the GPU millions of independent threads.
    private const int BatchSize = 1 << 24; // 16 M candidates per GPU launch

    /// <summary>
    /// Detects all usable CUDA/OpenCL device options. Each backend gets its own
    /// isolated Context so a broken OpenCL driver cannot crash CUDA detection.
    /// A device option is returned only if the actual crack kernel compiles.
    /// </summary>
    public static IReadOnlyList<GpuDeviceOption> DetectAvailableGpus()
    {
        return DetectAvailableGpus(out _);
    }

    public static IReadOnlyList<GpuDeviceOption> DetectAvailableGpus(out IReadOnlyList<GpuDetectionIssue> skippedDevices)
    {
        var devices = new List<GpuDeviceOption>();
        var skipped = new List<GpuDetectionIssue>();

        try
        {
            using var ctx = Context.Create(b => b.Cuda());
            int deviceIndex = 0;
            foreach (CudaDevice _ in ctx.GetCudaDevices())
            {
                string deviceInfo = $"CUDA device {deviceIndex}";
                try
                {
                    using var acc = ctx.CreateCudaAccelerator(deviceIndex);
                    ProbeKernelCompilation(acc);
                    deviceInfo = $"{acc.Name}  ({acc.MemorySize / 1024 / 1024} MB memory)  [CUDA device {deviceIndex}]";
                    devices.Add(new GpuDeviceOption(
                        GpuBackend.Cuda,
                        deviceIndex,
                        deviceInfo));
                }
                catch (Exception ex)
                {
                    skipped.Add(new GpuDetectionIssue(
                        GpuBackend.Cuda,
                        deviceIndex,
                        deviceInfo,
                        FormatDetectionError(ex)));
                }

                deviceIndex++;
            }
        }
        catch { }

        try
        {
            using var ctx = Context.Create(b => b.OpenCL(_ => true));
            int deviceIndex = 0;
            foreach (CLDevice device in ctx.GetCLDevices())
            {
                string deviceInfo =
                    $"{device.Name}  ({device.MemorySize / 1024 / 1024} MB memory)  [OpenCL device {deviceIndex}, {device.VendorName}, {device.DeviceType}]";
                try
                {
                    using var acc = ctx.CreateCLAccelerator(deviceIndex);
                    ProbeKernelCompilation(acc);
                    devices.Add(new GpuDeviceOption(
                        GpuBackend.OpenCL,
                        deviceIndex,
                        deviceInfo));
                }
                catch (Exception ex)
                {
                    skipped.Add(new GpuDetectionIssue(
                        GpuBackend.OpenCL,
                        deviceIndex,
                        deviceInfo,
                        FormatDetectionError(ex)));
                }

                deviceIndex++;
            }
        }
        catch { }

        skippedDevices = skipped;
        return devices;
    }

    /// <summary>
    /// Detects the preferred GPU backend: CUDA first, then OpenCL.
    /// Returns null if no GPU is available or if the crack kernel cannot compile.
    /// </summary>
    public static GpuDeviceOption? DetectGpu()
    {
        var devices = DetectAvailableGpus();
        return devices.Count > 0 ? devices[0] : null;
    }

    private static void ProbeKernelCompilation(Accelerator accelerator)
    {
        // Creating an accelerator only proves that the driver can be opened.
        // It does not prove that our C# kernel can be translated to CUDA PTX
        // or OpenCL code. This loads the actual crack kernel as a smoke test,
        // so "GPU detected" means "this backend can run our kernel".
        //
        // The generic type list is the kernel signature, minus the method name.
        // It must match CrackKernel exactly. Only blittable value types are
        // allowed here; for example, the SHA choice is passed as int 0/1
        // instead of bool because ILGPU 1.5.3 rejects bool kernel parameters.
        accelerator.LoadAutoGroupedStreamKernel<
            Index1D, long, long,
            ArrayView1D<byte, Stride1D.Dense>, int, int, int,
            ArrayView1D<byte, Stride1D.Dense>, int, int, int,
            ArrayView1D<byte, Stride1D.Dense>,
            ArrayView1D<int, Stride1D.Dense>,
            ArrayView1D<byte, Stride1D.Dense>>(CrackKernel);
    }

    private static string FormatDetectionError(Exception ex)
    {
        var root = ex.GetBaseException();
        return $"{root.GetType().Name}: {root.Message}";
    }

    public static GpuCrackResult Crack(
        string targetHashHex,
        BinEntry bin,
        bool useSha256,
        byte[] salt,
        GpuBackend backend,
        IProgress<(long tried, long total, TimeSpan elapsed)>? progress = null)
    {
        return Crack(
            targetHashHex,
            bin,
            useSha256,
            salt,
            new GpuDeviceOption(backend, 0, $"{backend} device 0"),
            progress);
    }

    public static GpuCrackResult Crack(
        string targetHashHex,
        BinEntry bin,
        bool useSha256,
        byte[] salt,
        GpuDeviceOption device,
        IProgress<(long tried, long total, TimeSpan elapsed)>? progress = null)
    {
        // For a 16-digit card with a 6-digit BIN:
        //   6 fixed BIN digits + 9 unknown digits + 1 Luhn check digit.
        // The GPU iterates only the 9 unknown digits. The Luhn digit is
        // deterministic, so it is calculated inside the kernel for each thread.
        int freeDigits = bin.CardLength - bin.Prefix.Length - 1;
        long total = 1;
        for (int i = 0; i < freeDigits; i++) total *= 10;

        // CPU-side inputs are converted to compact byte arrays once. The GPU
        // receives bytes, not strings, because strings allocate managed objects
        // and cannot be used inside an ILGPU kernel.
        byte[] targetHash = Convert.FromHexString(targetHashHex);
        byte[] binBytes   = Encoding.ASCII.GetBytes(bin.Prefix);
        int    saltLength = salt.Length;

        // Context owns compiler/backend state. Accelerator is the actual GPU
        // device handle. Keep both alive for the whole cracking operation.
        using var context     = device.Backend == GpuBackend.Cuda
            ? Context.Create(b => b.Cuda())
            : Context.Create(b => b.OpenCL(_ => true));
        using var accelerator = device.Backend == GpuBackend.Cuda
            ? (Accelerator)context.CreateCudaAccelerator(device.DeviceIndex)
            : context.CreateCLAccelerator(device.DeviceIndex);

        // d* variables are GPU buffers. Allocate1D copies the initial CPU
        // arrays to device memory for read-only inputs. dFound and dFoundCard
        // are tiny output buffers shared by all GPU threads.
        using var dBin       = accelerator.Allocate1D(binBytes);
        using var dTarget    = accelerator.Allocate1D(targetHash);
        // Salt buffer: allocate at least 1 byte because ILGPU does not allow
        // zero-length device allocations on every backend.
        using var dSalt      = accelerator.Allocate1D(saltLength > 0 ? salt : new byte[1]);
        using var dFound     = accelerator.Allocate1D<int>(1);
        using var dFoundCard = accelerator.Allocate1D<byte>(bin.CardLength);

        // -1 means "no match yet". When any thread finds a match it stores
        // its candidate index here, and the CPU checks this marker after each
        // batch. int is enough because one batch contains at most 16M items.
        dFound.CopyFromCPU([-1]);

        // The delegate type is verbose because GPU kernels do not use normal
        // C# reflection at launch time. ILGPU needs a strongly typed launcher
        // whose parameters line up exactly with CrackKernel.
        Action<Index1D, long, long,
            ArrayView1D<byte, Stride1D.Dense>, int, int, int,
            ArrayView1D<byte, Stride1D.Dense>, int, int, int,
            ArrayView1D<byte, Stride1D.Dense>,
            ArrayView1D<int, Stride1D.Dense>,
            ArrayView1D<byte, Stride1D.Dense>> kernel;
        try
        {
            kernel = accelerator.LoadAutoGroupedStreamKernel<
                Index1D, long, long,
                ArrayView1D<byte, Stride1D.Dense>, int, int, int,
                ArrayView1D<byte, Stride1D.Dense>, int, int, int,
                ArrayView1D<byte, Stride1D.Dense>,
                ArrayView1D<int, Stride1D.Dense>,
                ArrayView1D<byte, Stride1D.Dense>>(CrackKernel);
        }
        catch (Exception ex)
        {
            throw new NotSupportedException(
                $"Kernel compilation failed on {accelerator.Name} ({device.Backend} device {device.DeviceIndex}). " +
                "This GPU/driver does not support ILGPU kernels. " +
                "Run CardHashDemo.Cpu instead.", ex);
        }

        var sw = System.Diagnostics.Stopwatch.StartNew();
        long tried = 0;
        string? foundCard = null;

        for (long offset = 0; offset < total; offset += BatchSize)
        {
            long batchLen = Math.Min(BatchSize, total - offset);

            // Launch one GPU thread per candidate in this batch. index.X in
            // CrackKernel runs from 0 to batchLen-1; batchOffset converts that
            // local thread id into the global candidate number.
            kernel(
                (int)batchLen,
                offset, total,
                dBin.View, bin.Prefix.Length, bin.CardLength, freeDigits,
                dTarget.View, targetHash.Length, useSha256 ? 1 : 0,
                saltLength, dSalt.View,
                dFound.View, dFoundCard.View);

            // GPU launches are asynchronous. Synchronize waits until every
            // thread in this batch has finished before the CPU reads dFound.
            accelerator.Synchronize();
            tried += batchLen;

            // Only one integer is copied back per batch, so CPU/GPU transfer
            // overhead stays tiny. If a card was found, copy the full 16-byte
            // card result and stop launching more batches.
            int[] foundBuf = new int[1];
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

    // This method is compiled by ILGPU into GPU code. It does not run as a
    // normal C# method on the CPU. Important consequences:
    //
    //   * No managed allocations inside the kernel: no strings, arrays, LINQ,
    //     List<T>, exceptions, or heap objects.
    //   * Parameters must be blittable: primitive numbers and ArrayView buffers.
    //   * Each thread executes this method for one candidate card number.
    //
    // ArrayView1D<T> is a view into GPU memory. The CPU allocated these
    // buffers above; the kernel only reads/writes through the views.
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
        int useSha256,
        int saltLength,
        ArrayView1D<byte, Stride1D.Dense> salt,
        ArrayView1D<int, Stride1D.Dense> foundIndex,
        ArrayView1D<byte, Stride1D.Dense> foundCard)
    {
        // Convert this thread's local index into the global candidate number.
        // Example: if batchOffset is 33,554,432 and index.X is 10, this thread
        // checks candidate 33,554,442.
        long candidateIdx = batchOffset + index.X;

        // Stop useless work when:
        //   1. the last batch is shorter than BatchSize, or
        //   2. another thread already found a matching card.
        if (candidateIdx >= totalCombinations || foundIndex[0] >= 0) return;

        // This demo GPU kernel is specialized for the 16-digit BIN path used
        // by Program.cs. The first six digits come from the selected BIN.
        byte b0=bin[0], b1=bin[1], b2=bin[2], b3=bin[3], b4=bin[4], b5=bin[5];

        // Decode candidateIdx into nine decimal digits. We fill from right to
        // left so candidate 0 becomes 000000000, candidate 1 becomes
        // 000000001, and so on.
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

        // From rightmost partial digit (d14) going left, double every other
        // digit starting at d14. The Luhn check digit is derived, not searched.
        static int DD(byte b, bool dbl) { int v=b-48; if(dbl){v*=2;if(v>9)v-=9;} return v; }
        int s = DD(d14,true) +DD(d13,false)+DD(d12,true) +DD(d11,false)+DD(d10,true)
              + DD(d09,false)+DD(d08,true) +DD(d07,false)+DD(d06,true)
              + DD(b5,false) +DD(b4,true)  +DD(b3,false) +DD(b2,true)
              + DD(b1,false) +DD(b0,true);
        byte d15 = (byte)('0' + (10 - s % 10) % 10);

        // SHA1 and SHA256 both process 64-byte blocks. Our inputs are small:
        //   no salt:       16 bytes
        //   16-byte salt:  32 bytes
        // so the whole message always fits in a single SHA block.
        //
        // pm0..pm15 are the 16 big-endian 32-bit words of that padded block.
        // They are kept as scalar uint variables because GPU kernels cannot
        // allocate a managed uint[16] array.
        uint pm0,pm1,pm2,pm3,pm4,pm5,pm6,pm7,pm8,pm9,pm10,pm11,pm12,pm13,pm14,pm15;
        pm9=pm10=pm11=pm12=pm13=0;

        if (saltLength == 0)
        {
            // SHA padding is: original bytes, 0x80, zeros, then bit length.
            // 16 bytes * 8 = 128 bits, so W[15] is 128.
            pm0 = ((uint)b0 <<24)|((uint)b1 <<16)|((uint)b2 <<8)|b3;
            pm1 = ((uint)b4 <<24)|((uint)b5 <<16)|((uint)d06<<8)|d07;
            pm2 = ((uint)d08<<24)|((uint)d09<<16)|((uint)d10<<8)|d11;
            pm3 = ((uint)d12<<24)|((uint)d13<<16)|((uint)d14<<8)|d15;
            pm4 = 0x80000000u;
            pm5=pm6=pm7=pm8=0;
            pm14=0; pm15=128u;
        }
        else
        {
            // 16-byte salt is stored in W[0..3], followed by the card in
            // W[4..7]. 32 bytes * 8 = 256 bits, so W[15] is 256.
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

        bool match;
        if (useSha256 == 0)
        {
            // SHA1 returns five 32-bit words. The target hash is a byte array
            // in normal big-endian digest order, so each word is compared one
            // byte at a time: high byte first, low byte last.
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
            // SHA256 is the same idea but returns eight 32-bit words.
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

        // ILGPU's parameter order is target, compare, value. That differs
        // from System.Threading.Interlocked.CompareExchange, whose order is
        // target, value, compare.
        if (match && Atomic.CompareExchange(ref foundIndex[0], -1, (int)candidateIdx) == -1)
        {
            foundCard[0]=b0;  foundCard[1]=b1;  foundCard[2]=b2;  foundCard[3]=b3;
            foundCard[4]=b4;  foundCard[5]=b5;  foundCard[6]=d06; foundCard[7]=d07;
            foundCard[8]=d08; foundCard[9]=d09; foundCard[10]=d10;foundCard[11]=d11;
            foundCard[12]=d12;foundCard[13]=d13;foundCard[14]=d14;foundCard[15]=d15;
        }
    }
}
