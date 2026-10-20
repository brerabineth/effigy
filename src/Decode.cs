using System.Text.RegularExpressions;

namespace Effigy;

/// <summary>
/// Encoded-payload and obfuscation census over the free-text surface of a
/// shortcut (command-line arguments, icon/working-dir strings, overlay bytes,
/// decoded payloads). Grounded in the 2025-2026 LNK literature: in-argument
/// scripts, XOR-decoder functions, base64/hex blobs and char-code concat.
/// </summary>
public static partial class Decode
{
    [GeneratedRegex(@"[A-Za-z0-9+/]{32,}={0,2}")]
    private static partial Regex Base64Run();

    [GeneratedRegex(@"(?:[0-9a-fA-F]{2}){24,}")]
    private static partial Regex HexRun();

    [GeneratedRegex(@"https?://[^\s""'`<>\)\]]+|ftp://[^\s""'`<>\)\]]+")]
    private static partial Regex Url();

    [GeneratedRegex(@"\\\\[A-Za-z0-9_.\-]{2,}\\[^\s""']*")]
    private static partial Regex Unc();

    [GeneratedRegex(@"\b(?:\d{1,3}\.){3}\d{1,3}\b")]
    private static partial Regex Ipv4();

    [GeneratedRegex(@"\[char\]\s*\d{1,3}(\s*\+\s*\[char\]\s*\d{1,3}){3,}")]
    private static partial Regex CharConcat();

    public sealed class Payload
    {
        public required string Kind;         // base64 | hex | char-concat | xor-decoder
        public required string Raw;          // clipped raw form
        public string? Decoded;              // decoded text when printable
        public required int Offset;
        public required string Sha256;       // of decoded bytes (or raw when not decoded)
    }

    public sealed class Census
    {
        public List<Payload> Payloads = new();
        public List<string> Urls = new();
        public List<string> Uncs = new();
        public List<string> Ips = new();
        public bool HasCharConcat;
        public bool HasXorDecoder;
        public bool HasFromBase64Marker;
        public bool HasJoinMarker;
    }

    private static readonly string[] LolBins =
    {
        "powershell", "pwsh", "cmd.exe", "cmd ", "mshta", "rundll32", "regsvr32",
        "wscript", "cscript", "certutil", "bitsadmin", "msiexec", "msbuild",
        "installutil", "regasm", "regsvcs", "schtasks", "curl ", "wget ",
        "vssadmin", "wmic ", "scriptrunner", "syncappvpublishingserver",
    };

    private static readonly string[] CradleMarkers =
    {
        "iex", "invoke-expression", "invoke-command", "downloadstring",
        "downloadfile", "downloaddata", "webclient", "start-process",
        "net.webclient", "httpwebrequest", "get-wmiobject", "add-type",
    };

    private static readonly string[] EncodedSwitches =
    {
        "-enc", "-encodedcommand", " -e ", "/e:", "-ec ", " -encoded ",
    };

    private static readonly string[] HiddenSwitches =
    {
        "-w hidden", "-windowstyle hidden", "-win hidden", "-whidden",
        "/w hidden", "-window hidden", " -h ", "-noni -nop", "-nop -noni",
    };

    public static Census ScanText(string text)
    {
        var census = new Census();
        if (string.IsNullOrEmpty(text)) return census;

        foreach (Match m in Url().Matches(text))
            if (census.Urls.Count < 16) census.Urls.Add(m.Value);
        foreach (Match m in Unc().Matches(text))
            if (census.Uncs.Count < 16) census.Uncs.Add(m.Value);
        foreach (Match m in Ipv4().Matches(text))
            if (census.Ips.Count < 16) census.Ips.Add(m.Value);

        census.HasCharConcat = CharConcat().IsMatch(text);
        census.HasXorDecoder = HasXorDecoderPattern(text);
        census.HasFromBase64Marker =
            text.Contains("FromBase64String", StringComparison.OrdinalIgnoreCase) ||
            text.Contains("[Convert]::FromBase64", StringComparison.OrdinalIgnoreCase) ||
            text.Contains("base64 --decode", StringComparison.OrdinalIgnoreCase) ||
            text.Contains("certutil -decode", StringComparison.OrdinalIgnoreCase);
        census.HasJoinMarker =
            text.Contains("-join", StringComparison.OrdinalIgnoreCase) ||
            text.Contains("[string]::Join", StringComparison.OrdinalIgnoreCase);

        // Hex runs first; base64 runs that overlap an accepted hex span are the
        // same blob seen through a different lens and must not double-count.
        var taken = new List<(int start, int end)>();
        foreach (Match m in HexRun().Matches(text))
        {
            if (census.Payloads.Count >= 12) break;
            var p = TryHex(m.Value, m.Index);
            if (p != null)
            {
                census.Payloads.Add(p);
                taken.Add((m.Index, m.Index + m.Length));
            }
        }
        foreach (Match m in Base64Run().Matches(text))
        {
            if (census.Payloads.Count >= 12) break;
            int s = m.Index, e = m.Index + m.Length;
            if (taken.Any(t => s < t.end && e > t.start)) continue;
            var p = TryBase64(m.Value, m.Index, "base64");
            if (p != null) census.Payloads.Add(p);
        }
        return census;
    }

    private static bool HasXorDecoderPattern(string text)
    {
        bool bxor = text.Contains("-bxor", StringComparison.OrdinalIgnoreCase) ||
                    text.Contains(" ^ 0x", StringComparison.OrdinalIgnoreCase) ||
                    text.Contains("^key", StringComparison.OrdinalIgnoreCase) ||
                    text.Contains("^ 0x", StringComparison.Ordinal);
        bool loop = text.Contains("for($i", StringComparison.OrdinalIgnoreCase) ||
                    text.Contains("for ($i", StringComparison.OrdinalIgnoreCase) ||
                    text.Contains("foreach", StringComparison.OrdinalIgnoreCase) ||
                    text.Contains("while", StringComparison.OrdinalIgnoreCase);
        bool key = Regex.IsMatch(text, @"0x[0-9a-fA-F]{1,4}\b");
        return bxor && loop && key;
    }

    public static Payload? TryBase64(string raw, int offset, string kind)
    {
        // Tolerant: strip whitespace/newlines, then require a strict decode.
        string compact = Regex.Replace(raw, @"\s+", "");
        if (compact.Length < 32) return null;
        try
        {
            byte[] bytes = Convert.FromBase64String(compact);
            return BuildPayload(kind, raw, offset, bytes);
        }
        catch (FormatException) { return null; }
    }

    public static Payload? TryHex(string raw, int offset)
    {
        if (raw.Length < 48) return null;
        var bytes = new byte[raw.Length / 2];
        for (int i = 0; i < bytes.Length; i++)
        {
            int hi = HexVal(raw[i * 2]);
            int lo = HexVal(raw[i * 2 + 1]);
            if (hi < 0 || lo < 0) return null;
            bytes[i] = (byte)((hi << 4) | lo);
        }
        // Only treat hex runs as blobs when they decode to something meaningful:
        // printable text, or an embedded PE (MZ). Random hex-looking fragments of
        // other encodings must not inflate the score.
        var probe = BuildPayload("hex", raw, offset, bytes);
        bool mz = bytes.Length >= 2 && bytes[0] == 0x4D && bytes[1] == 0x5A;
        if (!mz && probe.Decoded is null) return null;
        return probe;
    }

    private static int HexVal(char ch) => ch switch
    {
        >= '0' and <= '9' => ch - '0',
        >= 'a' and <= 'f' => ch - 'a' + 10,
        >= 'A' and <= 'F' => ch - 'A' + 10,
        _ => -1,
    };

    private static Payload BuildPayload(string kind, string raw, int offset, byte[] bytes)
    {
        string text = System.Text.Encoding.UTF8.GetString(bytes);
        int printable = 0;
        foreach (char ch in text)
            if (ch >= 0x20 && ch < 0x7F || ch == '\n' || ch == '\r' || ch == '\t') printable++;
        double ratio = bytes.Length == 0 ? 0 : (double)printable / bytes.Length;
        string? decoded = ratio >= 0.85 && text.Length >= 8 ? text : null;
        return new Payload
        {
            Kind = kind,
            Raw = raw.Length > 80 ? raw[..80] + "..." : raw,
            Decoded = decoded,
            Offset = offset,
            Sha256 = Sha256Hex(bytes),
        };
    }

    public static bool MentionsLolBin(string text)
    {
        if (text is null) return false;
        string low = text.ToLowerInvariant();
        foreach (var bin in LolBins)
            if (low.Contains(bin)) return true;
        return false;
    }

    public static bool HasCradle(string text)
    {
        if (text is null) return false;
        string low = text.ToLowerInvariant();
        foreach (var m in CradleMarkers)
            if (low.Contains(m)) return true;
        return false;
    }

    public static bool HasEncodedSwitch(string text)
    {
        if (text is null) return false;
        string low = " " + text.ToLowerInvariant() + " ";
        foreach (var m in EncodedSwitches)
            if (low.Contains(m)) return true;
        return false;
    }

    public static bool HasHiddenSwitch(string text)
    {
        if (text is null) return false;
        string low = " " + text.ToLowerInvariant() + " ";
        foreach (var m in HiddenSwitches)
            if (low.Contains(m)) return true;
        return false;
    }

    public static string Sha256Hex(byte[] bytes)
    {
        byte[] hash = System.Security.Cryptography.SHA256.HashData(bytes);
        var sb = new System.Text.StringBuilder(hash.Length * 2);
        foreach (byte b in hash) sb.Append(b.ToString("x2"));
        return sb.ToString();
    }

    /// <summary>Document-like display names that droppers impersonate.</summary>
    public static readonly string[] DocumentExts =
    {
        ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
        ".jpg", ".jpeg", ".png", ".txt", ".rtf", ".hwp", ".one",
    };

    public static bool LooksLikeDocument(string? s)
    {
        if (string.IsNullOrEmpty(s)) return false;
        string low = s.ToLowerInvariant();
        foreach (var ext in DocumentExts)
            if (low.Contains(ext, StringComparison.Ordinal)) return true;
        return false;
    }

    /// <summary>LOLBin basenames that appear as LinkInfo targets in the wild.</summary>
    private static readonly HashSet<string> LolBinTargets = new()
    {
        "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh", "pwsh.exe",
        "mshta", "mshta.exe", "rundll32", "rundll32.exe", "regsvr32", "regsvr32.exe",
        "wscript", "wscript.exe", "cscript", "cscript.exe",
        "msbuild", "msbuild.exe", "installutil", "installutil.exe",
        "regasm", "regasm.exe", "regsvcs", "regsvcs.exe",
        "msiexec", "msiexec.exe", "schtasks", "schtasks.exe",
        "certutil", "certutil.exe", "bitsadmin", "bitsadmin.exe",
    };

    /// <summary>True when any path-like token in the resolved target is a LOLBin.
    /// Token-based so multi-part targets (local path + environment block) and
    /// backslash paths behave identically on every host OS.</summary>
    public static bool IsLolBinTarget(string? s)
    {
        if (string.IsNullOrEmpty(s)) return false;
        var tokens = s.ToLowerInvariant().Split(new[] { '\\', '/', ' ', '|', '\n', '\t', '"' },
            StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        foreach (var tok in tokens)
            if (LolBinTargets.Contains(tok)) return true;
        return false;
    }
}
