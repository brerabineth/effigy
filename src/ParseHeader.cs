namespace Effigy;

/// <summary>Header (SHELL_LINK_HEADER) + StringData section parsing.</summary>
public static class ParseHeader
{
    public const uint HeaderSize = 0x4C;
    public static readonly Guid ShellLinkClsid = new("00021401-0000-0000-C000-000000000046");

    // LinkFlags
    public const uint HasTargetIdList = 0x1;
    public const uint HasLinkInfo = 0x2;
    public const uint HasName = 0x4;
    public const uint HasRelativePath = 0x8;
    public const uint HasWorkingDir = 0x10;
    public const uint HasArguments = 0x20;
    public const uint HasIconLocation = 0x40;
    public const uint IsUnicode = 0x80;
    public const uint ForceNoLinkInfo = 0x100;
    public const uint HasExpString = 0x200;
    public const uint RunInSeparateProcess = 0x400;
    public const uint HasDarwinId = 0x1000;
    public const uint RunAsUser = 0x2000;
    public const uint HasExpIcon = 0x4000;
    public const uint NoPidlAlias = 0x8000;
    public const uint RunWithShimLayer = 0x20000;
    public const uint ForceNoLinkTrack = 0x40000;
    public const uint EnableTargetMetadata = 0x80000;
    public const uint DisableLinkPathTracking = 0x100000;
    public const uint DisableKnownFolderTracking = 0x200000;
    public const uint PreferEnvironmentPath = 0x2000000;
    public const uint KeepLocalIdListForUncTarget = 0x4000000;

    public static bool TryParse(Cursor c, LnkFile lnk)
    {
        if (!c.TryReadU32(out uint headerSize))
        {
            c.DiagAdd("header: file shorter than 4 bytes");
            return false;
        }
        if (headerSize != HeaderSize)
        {
            c.DiagAdd($"header: unexpected header size 0x{headerSize:X} (want 0x4C)");
            // Continue if there is still enough room; some writers lie about size.
        }
        if (!c.TryReadGuid(out Guid clsid))
        {
            c.DiagAdd("header: missing CLSID");
            return false;
        }
        lnk.HasValidHeaderClsid = clsid == ShellLinkClsid;
        if (!lnk.HasValidHeaderClsid)
            c.DiagAdd($"header: CLSID {clsid} is not the ShellLink CLSID");

        if (!c.TryReadU32(out lnk.LinkFlagsRaw)) { c.DiagAdd("header: missing LinkFlags"); return false; }
        if (!c.TryReadU32(out lnk.FileAttributesRaw)) { c.DiagAdd("header: missing FileAttributes"); return false; }
        if (!c.TryReadFileTime(out lnk.CreationTime)) { c.DiagAdd("header: missing CreationTime"); return false; }
        if (!c.TryReadFileTime(out lnk.AccessTime)) { c.DiagAdd("header: missing AccessTime"); return false; }
        if (!c.TryReadFileTime(out lnk.WriteTime)) { c.DiagAdd("header: missing WriteTime"); return false; }
        if (!c.TryReadU32(out lnk.FileSize)) { c.DiagAdd("header: missing FileSize"); return false; }
        if (!c.TryReadU32(out uint iconIndex)) { c.DiagAdd("header: missing IconIndex"); return false; }
        lnk.IconIndex = unchecked((int)iconIndex);
        if (!c.TryReadU32(out lnk.ShowCommand)) { c.DiagAdd("header: missing ShowCommand"); return false; }
        if (!c.TryReadU16(out lnk.HotKey)) { c.DiagAdd("header: missing HotKey"); return false; }
        if (!c.TrySkip(10)) { c.DiagAdd("header: missing reserved bytes"); return false; }

        uint f = lnk.LinkFlagsRaw;
        lnk.HasTargetIdList = (f & HasTargetIdList) != 0;
        lnk.HasLinkInfo = (f & HasLinkInfo) != 0;
        lnk.HasName = (f & HasName) != 0;
        lnk.HasRelativePath = (f & HasRelativePath) != 0;
        lnk.HasWorkingDir = (f & HasWorkingDir) != 0;
        lnk.HasArguments = (f & HasArguments) != 0;
        lnk.HasIconLocation = (f & HasIconLocation) != 0;
        lnk.IsUnicode = (f & IsUnicode) != 0;
        lnk.ForceNoLinkInfo = (f & ForceNoLinkInfo) != 0;
        lnk.HasExpString = (f & HasExpString) != 0;
        lnk.RunInSeparateProcess = (f & RunInSeparateProcess) != 0;
        lnk.HasDarwinId = (f & HasDarwinId) != 0;
        lnk.RunAsUser = (f & RunAsUser) != 0;
        lnk.HasExpIcon = (f & HasExpIcon) != 0;
        lnk.NoPidlAlias = (f & NoPidlAlias) != 0;
        lnk.RunWithShimLayer = (f & RunWithShimLayer) != 0;
        lnk.ForceNoLinkTrack = (f & ForceNoLinkTrack) != 0;
        lnk.EnableTargetMetadata = (f & EnableTargetMetadata) != 0;
        lnk.DisableLinkPathTracking = (f & DisableLinkPathTracking) != 0;
        lnk.DisableKnownFolderTracking = (f & DisableKnownFolderTracking) != 0;
        lnk.PreferEnvironmentPath = (f & PreferEnvironmentPath) != 0;
        lnk.KeepLocalIdListForUncTarget = (f & KeepLocalIdListForUncTarget) != 0;
        return true;
    }

    /// <summary>
    /// StringData: one COUNTFIELDS (u16, in characters) + characters per flag,
    /// character width chosen by the IsUnicode header flag (1.6.1 of MS-SHLLINK).
    /// </summary>
    public static bool TryParseStrings(Cursor c, LnkFile lnk)
    {
        bool wide = lnk.IsUnicode;
        bool ok = true;
        if (lnk.HasName) ok &= ReadStr(c, wide, v => lnk.NameLabel = v, "name");
        if (lnk.HasRelativePath) ok &= ReadStr(c, wide, v => lnk.RelativePath = v, "relative_path");
        if (lnk.HasWorkingDir) ok &= ReadStr(c, wide, v => lnk.WorkingDir = v, "working_dir");
        if (lnk.HasArguments) ok &= ReadStr(c, wide, v => lnk.Arguments = v, "arguments");
        if (lnk.HasIconLocation) ok &= ReadStr(c, wide, v => lnk.IconLocation = v, "icon_location");
        return ok;
    }

    private static bool ReadStr(Cursor c, bool wide, Action<string> assign, string what)
    {
        if (!c.TryReadU16(out ushort countChars))
        {
            c.DiagAdd($"strings: {what} count missing");
            return false;
        }
        int bytes = countChars * (wide ? 2 : 1);
        if (c.Remaining < bytes)
        {
            c.DiagAdd($"strings: {what} truncated ({bytes} wanted, {c.Remaining} left)");
            c.TrySkip(c.Remaining);
            return false;
        }
        byte[] raw = c.Peek(bytes);
        c.TrySkip(bytes);

        string s;
        if (wide)
        {
            // Read u16 code units directly so malformed data cannot throw.
            var sb = new System.Text.StringBuilder(countChars);
            for (int i = 0; i + 1 < raw.Length; i += 2)
            {
                ushort unit = (ushort)(raw[i] | (raw[i + 1] << 8));
                sb.Append((char)unit);
            }
            s = sb.ToString();
        }
        else
        {
            // CP1252-ish: map bytes to Latin-1 chars; control bytes shown as-is.
            var sb = new System.Text.StringBuilder(raw.Length);
            foreach (byte b in raw) sb.Append((char)b);
            s = sb.ToString();
        }
        assign(s.TrimEnd('\0'));
        return true;
    }
}
