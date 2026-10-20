namespace Effigy;

/// <summary>ExtraData blocks — [MS-SHLLINK] 2.6, walked until a zero-size terminal block.</summary>
public static class ParseBlocks
{
    public const uint EnvironmentVariable = 0xA0000001;
    public const uint ConsoleData = 0xA0000002;
    public const uint Tracker = 0xA0000003;
    public const uint ConsoleFe = 0xA0000004;
    public const uint SpecialFolder = 0xA0000005;
    public const uint Darwin = 0xA0000006;
    public const uint IconEnvironment = 0xA0000007;
    public const uint ShimLayer = 0xA0000008;
    public const uint PropertyStore = 0xA0000009;
    public const uint KnownFolder = 0xA000000A;
    public const uint VistaAndAboveIdList = 0xA000000B;

    public static string NameOf(uint sig) => sig switch
    {
        EnvironmentVariable => "environment-variable",
        ConsoleData => "console",
        Tracker => "tracker",
        ConsoleFe => "console-codepage",
        SpecialFolder => "special-folder",
        Darwin => "darwin-msi",
        IconEnvironment => "icon-environment",
        ShimLayer => "shim-layer",
        PropertyStore => "property-store",
        KnownFolder => "known-folder",
        VistaAndAboveIdList => "vista-idlist",
        _ => "unknown-0x" + sig.ToString("X8"),
    };

    /// <summary>
    /// Walk the ExtraData region. Returns (position after walk, sawTerminal).
    /// Guard rails: block size must be >= 8, must fit in the region, and the
    /// walk hard-stops after 64 blocks so a hostile file cannot spin forever.
    /// </summary>
    public static (int endPos, bool sawTerminal) Walk(Cursor c, LnkFile lnk, Diagnostics diag)
    {
        bool sawTerminal = false;
        int blocks = 0;
        while (c.Remaining >= 4 && blocks < 64)
        {
            blocks++;
            if (!c.TryReadU32(out uint blockSize)) { diag.Add("extrablocks: size missing"); break; }
            if (blockSize == 0) { sawTerminal = true; break; }
            if (blockSize < 8) { diag.Add($"extrablocks: degenerate block size {blockSize}"); break; }
            if (blockSize > c.Remaining + 4) { diag.Add("extrablocks: block overruns buffer"); lnk.Truncated = true; break; }
            if (!c.TryReadU32(out uint sig)) break;

            var block = new GenericBlock { Signature = sig, Size = blockSize, Offset = c.Pos - 8 };
            int bodyEnd = c.Pos - 8 + (int)blockSize;
            int bodyLen = (int)blockSize - 8;
            ReadBody(c, sig, Math.Min(bodyLen, c.Remaining), lnk, diag);
            lnk.ExtraBlocks.Add(block);
            if (!c.Seek(Math.Min(bodyEnd, c.Pos))) break;
        }
        return (c.Pos, sawTerminal);
    }

    private static void ReadBody(Cursor c, uint sig, int bodyLen, LnkFile lnk, Diagnostics diag)
    {
        switch (sig)
        {
            case EnvironmentVariable: ReadAnsiUnicodePair(c, bodyLen, out _, out var envU); lnk.EnvironmentTarget = envU ?? ReadAnsiHalf(c, bodyLen); break;
            case Tracker: ReadTracker(c, bodyLen, lnk, diag); break;
            case SpecialFolder: if (c.TryReadU32(out uint spid)) lnk.SpecialFolderId = spid; break;
            case KnownFolder:
                if (c.TryReadGuid(out Guid kf)) lnk.KnownFolderId = kf;
                c.TrySkip(4); // offset
                break;
            case Darwin: ReadAnsiUnicodePair(c, bodyLen, out _, out var darwinU); lnk.DarwinId = darwinU ?? ReadAnsiHalf(c, bodyLen); break;
            case IconEnvironment: ReadAnsiUnicodePair(c, bodyLen, out _, out var iconU); lnk.IconLocation ??= iconU ?? ReadAnsiHalf(c, bodyLen); break;
            case ShimLayer: ReadAnsiUnicodePair(c, bodyLen, out _, out var shimU); lnk.ShimLayer = shimU ?? ReadAnsiHalf(c, bodyLen); break;
            case ConsoleFe: if (c.TryReadU32(out uint cp)) lnk.ConsoleFeCodePage = unchecked((int)cp); break;
            case PropertyStore: ReadPropertyStore(c, bodyLen, lnk, diag); break;
            case VistaAndAboveIdList:
            {
                var (items, ok) = ParseItems.ReadIdList(c, diag);
                if (ok) lnk.VistaIdList = items;
                break;
            }
            default: c.TrySkip(bodyLen); break; // console blocks and unknowns: bytes kept in file only
        }
    }

    /// <summary>Environment/Darwin/Shim/IconEnv blocks carry ANSI (260B) then UTF-16 (520B) copies.</summary>
    private static void ReadAnsiUnicodePair(Cursor c, int bodyLen, out string? ansi, out string? unicode)
    {
        ansi = null; unicode = null;
        if (bodyLen >= 260)
        {
            ansi = ParseItems.ReadAnsiZ(c, 260);
            if (bodyLen >= 260 + 520)
            {
                byte[] raw = c.Peek(520);
                var sb = new System.Text.StringBuilder(260);
                for (int i = 0; i + 1 < raw.Length; i += 2)
                    sb.Append((char)(raw[i] | (raw[i + 1] << 8)));
                string s = sb.ToString().TrimEnd('\0');
                unicode = s.Length > 0 ? s : null;
                c.TrySkip(520);
            }
        }
        else
        {
            ansi = ParseItems.ReadAnsiZ(c, Math.Max(0, bodyLen));
        }
    }

    private static string? ReadAnsiHalf(Cursor c, int bodyLen)
    {
        // Fallback for truncated pairs: whatever ANSI bytes remain readable.
        return ParseItems.ReadAnsiZ(c, Math.Max(0, Math.Min(bodyLen, c.Remaining)));
    }

    private static void ReadTracker(Cursor c, int bodyLen, LnkFile lnk, Diagnostics diag)
    {
        if (!c.TryReadU32(out uint size)) return;
        if (!c.TryReadU32(out uint version)) return;
        if (bodyLen < 8 + 16 + 32 + 32) { diag.Add("tracker: truncated"); lnk.Truncated = true; return; }
        var t = new TrackerData { Version = version };
        if (!c.TryReadGuid(out t.MachineId)) return;
        if (!c.TryReadGuid(out t.DroidVolume)) return;
        if (!c.TryReadGuid(out t.DroidFile)) return;
        if (!c.TryReadGuid(out t.DroidBirthVolume)) return;
        if (!c.TryReadGuid(out t.DroidBirthFile)) return;
        lnk.Tracker = t;
    }

    private static void ReadPropertyStore(Cursor c, int bodyLen, LnkFile lnk, Diagnostics diag)
    {
        if (!c.TryReadU32(out uint storeSize)) return;
        if (!c.TryReadU32(out uint version)) return;
        if (!c.TryReadU32(out uint formatId)) return;
        if (!c.TryReadU32(out uint numProps)) return;
        int read = 0;
        while (read < numProps && numProps < 64)
        {
            read++;
            if (c.Remaining < 4) { diag.Add("propstore: truncated"); break; }
            if (!c.TryReadU32(out uint propSize)) break;
            if (propSize < 10 || propSize > c.Remaining + 4) { diag.Add("propstore: bad entry size"); break; }
            int entryEnd = c.Pos - 4 + (int)propSize;
            if (!c.TryReadU32(out uint propVersion)) break;
            if (!c.TryReadGuid(out Guid fmt)) break;
            if (!c.TryReadU32(out uint propId)) break;
            var entry = new PropStoreEntry { FormatId = fmt, PropertyId = propId };
            if (c.TryReadU16(out ushort valueType))
            {
                entry.ValueType = valueType;
                c.TrySkip(2); // padding
                int dataLeft = entryEnd - c.Pos;
                if (valueType == 0x1F && dataLeft > 4) // VT_LPWSTR
                {
                    c.TryReadU32(out uint chars);
                    int want = Math.Min((int)Math.Min(chars, 512) * 2, dataLeft - 4);
                    byte[] raw = c.Peek(want);
                    var sb = new System.Text.StringBuilder(want / 2);
                    for (int i = 0; i + 1 < raw.Length; i += 2)
                        sb.Append((char)(raw[i] | (raw[i + 1] << 8)));
                    entry.StrValue = sb.ToString().TrimEnd('\0');
                }
                else if (valueType == 0x13 && dataLeft >= 4) // VT_UI4
                {
                    if (c.TryReadU32(out uint iv)) entry.IntValue = iv;
                }
            }
            lnk.PropertyStore.Add(entry);
            if (!c.Seek(entryEnd)) break;
        }
    }
}
