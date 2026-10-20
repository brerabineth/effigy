namespace Effigy;

/// <summary>
/// Bounds-checked cursor over attacker-controlled bytes.
/// Every read is a Try* that returns false instead of throwing when the
/// buffer is exhausted, so a malformed or truncated .lnk can never crash
/// the parser. Diagnostics are collected on the <see cref="Diag"/> list.
/// </summary>
public sealed class Cursor
{
    private readonly byte[] _buf;
    public int Pos { get; private set; }
    public int Remaining => _buf.Length - Pos;
    public bool Eof => Pos >= _buf.Length;
    public List<string> Diag { get; } = new();

    public Cursor(byte[] buf)
    {
        _buf = buf ?? Array.Empty<byte>();
        Pos = 0;
    }

    public bool TryReadU8(out byte v)
    {
        v = 0;
        if (_buf.Length - Pos < 1) return false;
        v = _buf[Pos++];
        return true;
    }

    public bool TryReadU16(out ushort v)
    {
        v = 0;
        if (_buf.Length - Pos < 2) return false;
        v = (ushort)(_buf[Pos] | (_buf[Pos + 1] << 8));
        Pos += 2;
        return true;
    }

    public bool TryReadU32(out uint v)
    {
        v = 0;
        if (_buf.Length - Pos < 4) return false;
        v = (uint)(_buf[Pos] | (_buf[Pos + 1] << 8) | (_buf[Pos + 2] << 16) | (_buf[Pos + 3] << 24));
        Pos += 4;
        return true;
    }

    public bool TryReadU64(out ulong v)
    {
        v = 0;
        if (_buf.Length - Pos < 8) return false;
        ulong lo = (uint)(_buf[Pos] | (_buf[Pos + 1] << 8) | (_buf[Pos + 2] << 16) | (_buf[Pos + 3] << 24));
        ulong hi = (uint)(_buf[Pos + 4] | (_buf[Pos + 5] << 8) | (_buf[Pos + 6] << 16) | (_buf[Pos + 7] << 24));
        v = lo | (hi << 32);
        Pos += 8;
        return true;
    }

    /// <summary>Windows FILETIME: 100ns ticks since 1601-01-01 (little-endian u64).</summary>
    public bool TryReadFileTime(out ulong ft)
        => TryReadU64(out ft);

    public bool TryReadGuid(out Guid guid)
    {
        guid = Guid.Empty;
        if (_buf.Length - Pos < 16) return false;
        Span<byte> tmp = stackalloc byte[16];
        for (int i = 0; i < 16; i++) tmp[i] = _buf[Pos + i];
        Pos += 16;
        guid = new Guid(tmp);
        return true;
    }

    /// <summary>Peek a range without consuming. Clamps to what remains.</summary>
    public byte[] Peek(int count)
    {
        int n = Math.Min(Math.Max(count, 0), _buf.Length - Pos);
        var outp = new byte[n];
        Array.Copy(_buf, Pos, outp, 0, n);
        return outp;
    }

    public bool TrySkip(int count)
    {
        if (count < 0 || _buf.Length - Pos < count) return false;
        Pos += count;
        return true;
    }

    /// <summary>Move to an absolute position; returns false (and does not move) if out of range.</summary>
    public bool Seek(int absolutePos)
    {
        if (absolutePos < 0 || absolutePos > _buf.Length) return false;
        Pos = absolutePos;
        return true;
    }

    public void DiagAdd(string message)
    {
        if (Diag.Count < 64) Diag.Add(message);
    }
}

public static class FileTime
{
    /// <summary>Unix seconds to FILETIME ticks (offset 11644473600s, 100ns granularity).</summary>
    public static ulong FromUnixSeconds(long unixSeconds)
        => (ulong)((unixSeconds + 11644473600L) * 10_000_000L);

    public static DateTime ToDateTime(ulong ft)
    {
        // FILETIME epoch is 1601-01-01. Clamp absurd values instead of throwing:
        // 2650467743999999999 == 9999-12-31T23:59:59.9999999Z.
        const ulong maxTicks = 2650467743999999999UL;
        ulong t = ft > maxTicks ? maxTicks : ft;
        return DateTimeOffset.FromFileTime((long)t).UtcDateTime;
    }

    public static string ToIso(ulong ft) => ToDateTime(ft).ToString("yyyy-MM-dd'T'HH:mm:ss'Z'");
}
