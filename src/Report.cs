using System.Text.Json;

namespace Effigy;

/// <summary>Terminal cards, canonical JSON and Markdown output.</summary>
public static class Report
{
    private static bool _color = true;
    public static void SetColor(bool enabled) => _color = enabled;

    private static string C(string code, string s) => _color ? "\x1b[" + code + "m" + s + "\x1b[0m" : s;
    private static string Bold(string s) => C("1", s);
    private static string Dim(string s) => C("2", s);
    private static string Red(string s) => C("31", s);
    private static string Yellow(string s) => C("33", s);
    private static string Cyan(string s) => C("36", s);
    private static string Green(string s) => C("32", s);

    public static string BandColor(Band b) => b switch
    {
        Band.Clean => Green("CLEAN"),
        Band.Watch => Yellow("WATCH"),
        Band.Suspicious => Red("SUSPICIOUS"),
        _ => Red("HOSTILE"),
    };

    public static string Terminal(Engine.Result r, string displayPath)
    {
        var sb = new System.Text.StringBuilder();
        sb.AppendLine(Dim("effigy v" + Cli.Version + " - windows shortcut triage"));
        sb.AppendLine();
        sb.AppendLine("  " + Bold(displayPath));
        var lnk = r.Lnk;
        string target = LnkParser.ResolveTarget(lnk);
        sb.AppendLine("  target    " + Cyan(target));
        if (lnk.RelativePath is string rp && rp.Length > 0)
            sb.AppendLine("  path      " + Cyan(rp));
        if (lnk.Arguments is string ar && ar.Length > 0)
        {
            string a = ar.Length > 160 ? ar[..160] + "..." : ar;
            sb.AppendLine("  args      " + Cyan(a));
        }
        if (lnk.IconLocation is string ic && ic.Length > 0)
            sb.AppendLine("  icon      " + Cyan(ic));
        sb.AppendLine("  times     " + Dim($"{FileTime.ToIso(lnk.CreationTime)} / {FileTime.ToIso(lnk.AccessTime)} / {FileTime.ToIso(lnk.WriteTime)}"));
        sb.AppendLine("  attrs     " + Dim($"0x{lnk.FileAttributesRaw:X8}  size={lnk.FileSize}  show={lnk.ShowCommand}"));
        if (lnk.Tracker is TrackerData t)
            sb.AppendLine("  tracker   " + Dim($"machine={t.MachineId:D}"));
        sb.AppendLine();
        if (r.Findings.Count == 0)
        {
            sb.AppendLine("  " + Green("no findings"));
        }
        else
        {
            int width = r.Findings.Max(f => f.Id.Length);
            foreach (var f in r.Findings)
            {
                string sev = f.Severity switch
                {
                    Severity.Critical => Red("critical"),
                    Severity.High => Red("high    "),
                    Severity.Medium => Yellow("medium  "),
                    Severity.Low => Yellow("low     "),
                    _ => Dim("info    "),
                };
                sb.AppendLine($"  {sev} {Cyan(f.Id.PadRight(width))}  {f.Weight,3}  {f.Detail}");
            }
        }
        sb.AppendLine();
        sb.AppendLine("  score     " + Bold(r.Score.ToString()) + Dim($"  band {Verdict.Name(r.Band)}"));
        sb.AppendLine("  verdict   " + BandColor(r.Band));
        return sb.ToString();
    }

    public static string Markdown(string displayPath, Engine.Result r)
    {
        var sb = new System.Text.StringBuilder();
        sb.AppendLine($"## `{displayPath}`");
        sb.AppendLine();
        sb.AppendLine($"**verdict:** {Verdict.Name(r.Band)} ({r.Score})  ");
        sb.AppendLine($"**target:** `{LnkParser.ResolveTarget(r.Lnk).Replace("|", @"\|")}`  ");
        sb.AppendLine($"**bytes:** {r.Lnk.SourceBytes}");
        sb.AppendLine();
        if (r.Findings.Count > 0)
        {
            sb.AppendLine("| severity | id | weight | detail |");
            sb.AppendLine("|----------|----|--------|--------|");
            foreach (var f in r.Findings)
            {
                string detail = f.Detail.Replace("|", @"\|").Replace("\n", " ");
                sb.AppendLine($"| {f.Severity.ToString().ToLowerInvariant()} | `{f.Id}` | {f.Weight} | {detail} |");
            }
        }
        else
        {
            sb.AppendLine("_no findings_");
        }
        return sb.ToString();
    }

    /// <summary>Deep forensic dump for one file (show command).</summary>
    public static string Show(LnkFile lnk, string displayPath)
    {
        var sb = new System.Text.StringBuilder();
        sb.AppendLine(Dim("effigy v" + Cli.Version + " - deep dump"));
        sb.AppendLine();
        sb.AppendLine("  " + Bold(displayPath) + Dim($"  ({lnk.SourceBytes} bytes)"));
        sb.AppendLine("  header    " + Dim($"flags=0x{lnk.LinkFlagsRaw:X8} attrs=0x{lnk.FileAttributesRaw:X8}"));
        sb.AppendLine("  created   " + FileTime.ToIso(lnk.CreationTime));
        sb.AppendLine("  accessed  " + FileTime.ToIso(lnk.AccessTime));
        sb.AppendLine("  written   " + FileTime.ToIso(lnk.WriteTime));
        sb.AppendLine("  show      " + lnk.ShowCommand + Dim(lnk.ShowCommand switch { 3 => " (maximized)", 7 => " (minimized-no-active)", 1 => " (normal)", _ => "" }));
        sb.AppendLine("  hotkey    " + $"0x{lnk.HotKey:X4}");
        void Str(string name, string? v) { if (v != null) sb.AppendLine("  " + name.PadRight(9) + " " + Cyan(v.Length > 200 ? v[..200] + "..." : v)); }
        Str("name", lnk.NameLabel);
        Str("relpath", lnk.RelativePath);
        Str("workdir", lnk.WorkingDir);
        Str("args", lnk.Arguments);
        Str("icon", lnk.IconLocation);
        if (lnk.LinkInfo is LinkInfoData li)
        {
            sb.AppendLine("  linkinfo  " + Dim($"vol_type={li.VolumeDriveType} serial=0x{li.VolumeSerial:X8} label={li.VolumeLabel ?? "-"}"));
            if (li.LocalBasePath != null) sb.AppendLine("  localpath " + Cyan(li.LocalBasePath));
            if (li.NetName != null) sb.AppendLine("  netname   " + Cyan(li.NetName));
            if (li.NetDevice != null) sb.AppendLine("  netdev    " + Cyan(li.NetDevice));
            if (li.CommonPathSuffix != null) sb.AppendLine("  suffix    " + Cyan(li.CommonPathSuffix));
        }
        if (lnk.TargetIdList.Count > 0)
        {
            sb.AppendLine("  idlist    " + Dim($"{lnk.TargetIdList.Count} items"));
            foreach (var item in lnk.TargetIdList)
                sb.AppendLine("    - " + Cyan(item.Label ?? "?") + Dim($"  kind=0x{item.Kind:X2} size={item.Size}"));
        }
        if (lnk.ExtraBlocks.Count > 0)
        {
            sb.AppendLine("  blocks    " + Dim($"{lnk.ExtraBlocks.Count}"));
            foreach (var b in lnk.ExtraBlocks)
                sb.AppendLine("    - " + Cyan(b.DisplayName) + Dim($" sig=0x{b.Signature:X8} size={b.Size}"));
        }
        if (lnk.Tracker is TrackerData t2)
        {
            sb.AppendLine("  droids    " + Dim($"machine={t2.MachineId:D}"));
            sb.AppendLine("            " + Dim($"vol={t2.DroidVolume:D}"));
            sb.AppendLine("            " + Dim($"file={t2.DroidFile:D}"));
            sb.AppendLine("            " + Dim($"birth_vol={t2.DroidBirthVolume:D}"));
            sb.AppendLine("            " + Dim($"birth_file={t2.DroidBirthFile:D}"));
        }
        foreach (var p in lnk.PropertyStore)
        {
            string val = p.StrValue ?? (p.IntValue is uint iv ? iv.ToString() : $"type=0x{p.ValueType:X}");
            sb.AppendLine("  property  " + Cyan(p.FormatId.ToString("D") + "/" + p.PropertyId) + " = " + Dim(ClipText(val, 120)));
        }
        if (lnk.Overlay is byte[] ov && ov.Length > 0)
        {
            sb.AppendLine("  overlay   " + Dim($"{ov.Length} bytes"));
            int take = Math.Min(64, ov.Length);
            var hex = new System.Text.StringBuilder();
            foreach (byte b in ov[..take]) hex.Append(b.ToString("x2")).Append(' ');
            sb.AppendLine("            " + Dim(hex.ToString().TrimEnd() + (ov.Length > take ? " ..." : "")));
        }
        if (lnk.Diagnostics.Count > 0)
        {
            sb.AppendLine("  parser    " + Yellow($"{lnk.Diagnostics.Count} diagnostics"));
            foreach (var d in lnk.Diagnostics.Take(8)) sb.AppendLine("    ! " + Dim(d));
        }
        return sb.ToString();
    }

    private static string ClipText(string s, int n) => s.Length > n ? s[..n] + "..." : s;

    /// <summary>Aggregate JSON for multi-file scans (one line per file, inside a top array).</summary>
    public static string JsonBundle(List<(string path, Engine.Result r)> results)
    {
        using var ms = new MemoryStream();
        using (var w = new Utf8JsonWriter(ms, new JsonWriterOptions()))
        {
            w.WriteStartObject();
            w.WriteString("tool", "effigy");
            w.WriteString("version", Cli.Version);
            w.WriteNumber("files", results.Count);
            string worst = results.Count == 0 ? "clean" : Verdict.Name(results.Max(x => x.r.Band));
            w.WriteString("verdict", worst);
            w.WriteStartArray("results");
            foreach (var (path, r) in results)
                w.WriteRawValue(Verdict.ToJson(path, r.Band, r.Score, r.Findings, r.Lnk.Diagnostics, r.Lnk.SourceBytes), skipInputValidation: true);
            w.WriteEndArray();
            w.WriteEndObject();
        }
        return System.Text.Encoding.UTF8.GetString(ms.ToArray());
    }
}
