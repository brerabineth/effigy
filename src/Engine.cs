namespace Effigy;

/// <summary>Correlation layer: parse result + census -> findings, score, verdict.</summary>
public static class Engine
{
    public sealed class Result
    {
        public required LnkFile Lnk;
        public required List<Finding> Findings;
        public required int Score;
        public required Band Band;
        public Decode.Census? Census;
    }

    public static Result Analyze(byte[] data, string displayPath, Diagnostics diag)
    {
        var lnk = LnkParser.Parse(data, diag);

        // Free-text surface: arguments dominate, plus icon/working-dir/name.
        string textSurface = string.Join("\n",
            lnk.Arguments ?? "",
            lnk.IconLocation ?? "",
            lnk.WorkingDir ?? "",
            lnk.EnvironmentTarget ?? "");
        var census = Decode.ScanText(textSurface);
        var findings = new List<Finding>();
        void Add(RuleDef rule, string source, string detail) =>
            findings.Add(new Finding { Id = rule.Id, Severity = rule.Severity, Weight = rule.Weight, Source = source, Detail = detail });

        string target = LnkParser.ResolveTarget(lnk);
        bool targetIsLolbin = Decode.IsLolBinTarget(target);

        // --- arguments ---
        if (lnk.Arguments is string args && args.Length > 0)
        {
            if (Decode.HasEncodedSwitch(args)) Add(Rules.ArgsEncodedSwitch, "arguments", "encoded command switch present");
            if (Decode.HasHiddenSwitch(args)) Add(Rules.ArgsHiddenWindow, "arguments", "hidden window switch present");
            if (Decode.MentionsLolBin(args)) Add(Rules.ArgsLolbin, "arguments", Clip(args));
            if (Decode.HasCradle(args)) Add(Rules.ArgsIexCradle, "arguments", Clip(args));
            if (args.Length > 400) Add(Rules.ArgLengthExtreme, "arguments", $"length {args.Length}");
            if (args.Contains("cmd.exe /c", StringComparison.OrdinalIgnoreCase) ||
                args.Contains("cmd /c", StringComparison.OrdinalIgnoreCase) ||
                args.Contains("&&", StringComparison.Ordinal))
                Add(Rules.ArgsCmdChain, "arguments", "cmd chain or && in arguments");
        }

        // URL/UNC census covers the whole free-text surface (args, workdir, icon, env block).
        foreach (var u in census.Urls.Take(3))
            Add(Rules.ArgsRemotePayload, "text", Clip(u));
        foreach (var u in census.Uncs.Take(3))
            Add(Rules.ArgsUnc, "text", Clip(u));

        // --- decoded payloads ---
        foreach (var p in census.Payloads)
        {
            if (p.Kind == "base64") Add(Rules.EncodedBase64, "payload", $"{Clip(p.Raw)} sha256={p.Sha256[..16]}");
            if (p.Kind == "hex") Add(Rules.EncodedHex, "payload", $"hex run sha256={p.Sha256[..16]}");
            if (p.Decoded is string dec)
            {
                if (Decode.MentionsLolBin(dec) || Decode.HasCradle(dec))
                    Add(Rules.ArgsDecodedLolbin, "payload", $"decodes to: {Clip(dec)}");
                else if (Decode.HasCradle(dec))
                    Add(Rules.ArgsIexCradle, "payload", $"decoded cradle: {Clip(dec)}");
            }
        }
        if (census.HasXorDecoder) Add(Rules.ArgsXorDecoder, "arguments", "XOR decode loop with key literal");
        if (census.HasCharConcat) Add(Rules.ArgsLolbin, "arguments", "[char]-concat obfuscation");

        // --- target ---
        if (targetIsLolbin) Add(Rules.TargetLolbin, "target", Clip(target));
        if (lnk.LinkInfo?.HasCommonNetworkLink == true || lnk.LinkInfo?.NetName != null)
            Add(Rules.TargetRemote, "linkinfo", Clip("\\\\" + (lnk.LinkInfo.NetName ?? "?") + "\\" + (lnk.LinkInfo.CommonPathSuffix ?? "")));

        // document-name spoof: display surface looks like a document, target is a script host
        bool displayLooksDoc = Decode.LooksLikeDocument(lnk.RelativePath) ||
                               Decode.LooksLikeDocument(lnk.NameLabel);
        if (displayLooksDoc && (targetIsLolbin || (lnk.Arguments?.Length > 0 && Decode.MentionsLolBin(lnk.Arguments))))
            Add(Rules.SpoofDocumentName, "display", $"name says document, target is {Clip(target)}");

        // --- icon ---
        if (lnk.IconLocation is string icon && icon.Length > 0)
        {
            if (icon.StartsWith("\\\\", StringComparison.Ordinal) || icon.StartsWith("http", StringComparison.OrdinalIgnoreCase))
                Add(Rules.IconRemote, "icon", Clip(icon));
            if (Decode.LooksLikeDocument(icon))
                Add(Rules.IconDocument, "icon", Clip(icon));
            if (targetIsLolbin)
            {
                string iconBase = Path.GetFileName(icon.ToLowerInvariant().Trim());
                int comma = iconBase.IndexOf(',');
                if (comma >= 0) iconBase = iconBase[..comma]; // strip ",<index>" shell icon suffix
                string targetBase = Path.GetFileName(target.ToLowerInvariant().Trim());
                // shell resource icons (shell32.dll,index) count as mismatch for script hosts
                bool iconIsDocish = iconBase.EndsWith(".pdf") || iconBase.EndsWith(".doc") ||
                                    iconBase.EndsWith(".docx") || iconBase.EndsWith(".txt") ||
                                    iconBase.EndsWith(".jpg") || iconBase.EndsWith(".png");
                bool differs = iconBase != targetBase && (iconIsDocish || iconBase.EndsWith(".dll") || iconBase.EndsWith(".exe"));
                if (differs) Add(Rules.IconMismatch, "icon", $"icon {Clip(iconBase)} vs target {Clip(targetBase)}");
            }
        }

        // --- environment target ---
        if (lnk.EnvironmentTarget is string envT && envT.Length > 0)
        {
            string low = envT.ToLowerInvariant();
            if (low.Contains("%temp%") || low.Contains("%appdata%") || low.Contains("%public%") ||
                low.Contains("%programdata%") || low.Contains("%localappdata%") || low.Contains("\\windows\\"))
                Add(Rules.EnvVarExec, "environment-block", Clip(envT));
        }

        // --- extra blocks ---
        if (lnk.Tracker != null) Add(Rules.TrackerMachineId, "tracker-block", "machine " + lnk.Tracker.MachineId.ToString("D"));
        if (lnk.DarwinId != null) Add(Rules.DarwinMsi, "darwin-block", Clip(lnk.DarwinId));
        bool startupHit = (lnk.SpecialFolderId is 0x07 or 0x15) ||
                          (lnk.KnownFolderId is Guid kf &&
                           ParseItems.KnownFolders.TryGetValue(kf, out var kn) && kn == "startup");
        if (startupHit)
            Add(Rules.TargetStartup, "extra-blocks", "startup folder reference");
        foreach (var b in lnk.ExtraBlocks)
            if (b.Signature is not (ParseBlocks.ConsoleData or ParseBlocks.ConsoleFe or ParseBlocks.EnvironmentVariable
                or ParseBlocks.Tracker or ParseBlocks.SpecialFolder or ParseBlocks.KnownFolder or ParseBlocks.Darwin
                or ParseBlocks.IconEnvironment or ParseBlocks.ShimLayer or ParseBlocks.PropertyStore or ParseBlocks.VistaAndAboveIdList))
                Add(Rules.StructureUnknownBlock, "extra-blocks", b.DisplayName);

        // --- timestamps ---
        if (lnk.CreationTime == 0 && lnk.AccessTime == 0 && lnk.WriteTime == 0)
            Add(Rules.TimestampsZeroed, "header", "all three FILETIMEs zero");

        // --- window behavior ---
        if (lnk.ShowCommand == 7)
            Add(Rules.ShowCommandHidden, "header", "ShowCommand SW_SHOWMINNOACTIVE");

        // --- header / structure hygiene ---
        if (!lnk.HasValidHeaderClsid) Add(Rules.HeaderClsidUnknown, "header", "non-shell-link CLSID");
        if (lnk.Truncated || diag.Notes.Any(n => n.Contains("truncated", StringComparison.Ordinal)))
            Add(Rules.StructureTruncated, "parser", string.Join("; ", diag.Notes.Take(2)));

        // --- overlay ---
        if (lnk.Overlay is byte[] ov && ov.Length > 0)
        {
            Add(Rules.OverlayPresent, "overlay", $"{ov.Length} bytes past terminal block");
            string ovText = System.Text.Encoding.UTF8.GetString(ov);
            int printable = 0;
            foreach (char ch in ovText)
                if (ch >= 0x20 && ch < 0x7F || ch == '\n' || ch == '\r' || ch == '\t') printable++;
            double ratio = ov.Length == 0 ? 0 : (double)printable / ov.Length;
            bool scripty = ratio > 0.8 && ovText.Length > 24 &&
                (ovText.Contains('$') || ovText.Contains('(') || ovText.Contains('=') || ovText.Contains("http"));
            if (scripty) Add(Rules.OverlayScript, "overlay", Clip(ovText));
        }

        // Dedupe by id+detail, keep highest-weight instance.
        var deduped = findings
            .GroupBy(f => f.Id + "|" + f.Detail)
            .Select(g => g.First())
            .OrderByDescending(f => f.Weight)
            .ThenBy(f => f.Id, StringComparer.Ordinal)
            .ToList();

        // Multi-source rules collapse: one finding per id, merging details.
        var collapsed = deduped
            .GroupBy(f => f.Id)
            .Select(g => g.Count() == 1 ? g.First() : new Finding
            {
                Id = g.Key,
                Severity = g.First().Severity,
                Weight = g.First().Weight,
                Source = string.Join("+", g.Select(x => x.Source).Distinct(StringComparer.Ordinal)),
                Detail = g.First().Detail,
            })
            .OrderByDescending(f => f.Weight)
            .ThenBy(f => f.Id, StringComparer.Ordinal)
            .ToList();

        int score = collapsed.Sum(f => f.Weight);
        var band = Verdict.BandFor(score);
        return new Result { Lnk = lnk, Findings = collapsed, Score = score, Band = band, Census = census };
    }

    private static string Clip(string s) => s.Length > 90 ? s[..90] + "..." : s;
}
