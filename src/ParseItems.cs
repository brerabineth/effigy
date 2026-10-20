namespace Effigy;

/// <summary>
/// Shell item (IDList) parsing — [MS-SHLLINK] 2.5 LinkTargetIDList plus the
/// VistaAndAboveIDList extra block. Only a pragmatic subset of shell item
/// kinds is decoded; every byte position is bounds-checked.
/// </summary>
public static class ParseItems
{
    public static readonly Dictionary<Guid, string> RootGuids = new()
    {
        [new Guid("20D04FE0-3AEA-1069-A2D8-08002B30309D")] = "my-computer",
        [new Guid("208D2C60-3AEA-1069-A2D7-08002B30309D")] = "network",
        [new Guid("B4FB3F98-C1EA-428D-A78A-D1F5659CBA93")] = "other-devices",
        [new Guid("1AC14E77-02E7-4E5D-B744-2EB1AE5198B7")] = "windows-system",
        [new Guid("D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27")] = "windows-system64",
        [new Guid("905E63B6-C1BF-494E-B29C-65B732D3D21A")] = "program-files",
        [new Guid("6D809377-6AF0-444B-8957-A3773F02200E")] = "program-files64",
        [new Guid("F38BF404-1D43-42F2-9305-67DE0B28FC23")] = "windows",
        [new Guid("5E6C858F-0E22-4760-9AFE-EA3317B67173")] = "program-data",
        [new Guid("7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E")] = "program-files-x86",
        [new Guid("A52BBA46-E9E1-435F-B3D9-28DAA648C0F6")] = "computer-folder",
        [new Guid("D20BEEC4-5CA8-4905-AE3B-BF251EA09B53")] = "network-neighborhood",
        [new Guid("F02C1A0D-BE21-4350-88B0-7367FC96EF3C")] = "network-places",
        [new Guid("BD4EF23A-2A7F-46D7-AF0E-4C0BE3D3B4A7")] = "unknown-root",
    };

    public static readonly Dictionary<uint, string> SpecialFolders = new()
    {
        [0x00] = "desktop", [0x01] = "internet", [0x02] = "programs", [0x03] = "controls",
        [0x04] = "printers", [0x05] = "documents", [0x06] = "favorites", [0x07] = "startup",
        [0x08] = "recent", [0x09] = "sendto", [0x0A] = "start-menu", [0x0B] = "desktop-dir",
        [0x0C] = "music", [0x0D] = "movies", [0x10] = "desktop-slug", [0x11] = "computers",
        [0x13] = "fonts", [0x14] = "templates", [0x15] = "start-up-known", [0x16] = "appdata",
        [0x17] = "print-hood", [0x18] = "local-settings", [0x19] = "altstartup",
        [0x1A] = "local-appdata", [0x1B] = "windows-known", [0x1D] = "local-appdata-2",
        [0x1E] = "internet-cache", [0x1F] = "cookies", [0x20] = "history", [0x22] = "admin-tools",
        [0x23] = "search", [0x24] = "videos", [0x25] = "pictures", [0x27] = "profile",
    };

    public static readonly Dictionary<Guid, string> KnownFolders = new()
    {
        [new Guid("B97D20BB-F46A-4C97-BA10-5E3608430854")] = "startup",
        [new Guid("AE50C081-EBD2-438A-8655-8A092E34987A")] = "recent",
        [new Guid("AC563434-FD2F-4319-B1A0-3A5DC0A01312")] = "temp",
        [new Guid("1AC14E77-02E7-4E5D-B744-2EB1AE5198B7")] = "system32",
        [new Guid("F1B32785-6FBA-4FCF-9D55-7B8E7F157091")] = "local-appdata-known",
        [new Guid("2B0F765D-C0E9-4171-908E-08A611B84FF6")] = "start-menu-known",
        [new Guid("625B53C3-AB48-4EC1-BA1F-A1EF4146FC19")] = "start-menu-all",
    };

    /// <summary>Parse a length-prefixed IDList at the current position.</summary>
    public static (List<ShellItem> items, bool ok) ReadIdList(Cursor c, Diagnostics diag)
    {
        var items = new List<ShellItem>();
        if (!c.TryReadU16(out ushort listBytes))
        {
            diag.Add("idlist: size missing");
            return (items, false);
        }
        if (listBytes < 2)
        {
            diag.Add("idlist: degenerate size");
            return (items, false);
        }
        if (c.Remaining < listBytes)
        {
            diag.Add("idlist: size overruns buffer");
            return (items, false);
        }
        int end = c.Pos + listBytes;
        while (c.Pos + 2 <= end)
        {
            c.TryReadU16(out ushort itemSize);
            if (itemSize == 0) break; // TerminalID: clean end of list
            if (itemSize < 2 || c.Pos - 2 + itemSize > end) { diag.Add("idlist: malformed item size"); break; }
            int itemEnd = c.Pos - 2 + itemSize;
            var item = ReadOneItem(c, itemSize - 2, diag);
            items.Add(item);
            if (!c.Seek(itemEnd)) break;
        }
        c.Seek(Math.Min(end, c.Pos));
        return (items, true);
    }

    private static ShellItem ReadOneItem(Cursor c, int bodyLen, Diagnostics diag)
    {
        var item = new ShellItem();
        if (!c.TryReadU8(out item.Kind)) return item;

        if (item.Kind == 0x1F) // root folder by GUID
        {
            if (c.TryReadGuid(out Guid g) && RootGuids.TryGetValue(g, out var name))
            {
                item.RootGuid = name;
                item.Label = name;
                item.IsNetwork = name.Contains("network");
            }
            else
            {
                item.RootGuid = "root:" + Guid.Empty;
                item.Label = "root";
            }
            c.TrySkip(Math.Max(0, bodyLen - 17));
            return item;
        }
        if (item.Kind == 0x2F) // directory: ANSI name from +4
        {
            item.Label = ReadAnsiZ(c, bodyLen - 1);
            return item;
        }
        if (item.Kind >= 0x40 && item.Kind <= 0x4F) // drive
        {
            c.TrySkip(3); // sort order
            item.Drive = ReadAnsiZ(c, Math.Min(24, bodyLen - 4));
            item.Label = item.Drive;
            return item;
        }
        if (item.Kind == 0x61) // URI
        {
            c.TrySkip(1);
            item.IsUri = true;
            item.Uri = ReadAnsiZ(c, Math.Max(0, bodyLen - 2));
            item.Label = item.Uri;
            return item;
        }
        if (item.Kind == 0xC3) // folder with details
        {
            c.TrySkip(3);
            item.Label = ReadAnsiZ(c, Math.Max(0, bodyLen - 4));
            return item;
        }
        if (item.Kind < 0x40) // file / generic item with attributes in low nibble
        {
            byte flags = (byte)(item.Kind & 0x07);
            int off = 0;
            // Offsets after the type byte: primary name always at +0.
            item.Label = ReadAnsiZ(c, bodyLen - 1);
            if ((flags & 0x4) != 0) // has extension block
            {
                // Extension: 4 size bytes then fields; try to sniff sizes but stay defensive.
                off = item.Label?.Length ?? 0;
            }
            return item;
        }
        // Unknown kind: keep bytes as hex digest only.
        item.Label = "kind-0x" + item.Kind.ToString("X2");
        c.TrySkip(Math.Max(0, bodyLen - 1));
        return item;
    }

    /// <summary>Read a NUL-terminated ANSI string from the cursor without throwing.</summary>
    public static string ReadAnsiZ(Cursor c, int maxBytes)
    {
        var sb = new System.Text.StringBuilder();
        int taken = 0;
        while (taken < maxBytes && c.TryReadU8(out byte b))
        {
            taken++;
            if (b == 0) break;
            sb.Append((char)b);
        }
        // Skip the remainder so callers stay aligned.
        c.TrySkip(Math.Max(0, maxBytes - taken));
        return sb.ToString();
    }
}
