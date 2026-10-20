namespace Effigy;

/// <summary>Top-level parser: header -> strings -> IDList -> LinkInfo -> ExtraData -> overlay.</summary>
public static class LnkParser
{
    public static LnkFile Parse(byte[] data, Diagnostics diag)
    {
        var lnk = new LnkFile { SourceBytes = data.Length };
        var c = new Cursor(data);

        if (!ParseHeader.TryParse(c, lnk))
        {
            lnk.Truncated = true;
            foreach (var d in c.Diag) diag.Add(d);
            return lnk;
        }

        if (lnk.HasTargetIdList)
        {
            var (items, ok) = ParseItems.ReadIdList(c, diag);
            if (ok) lnk.TargetIdList = items;
        }

        if (lnk.HasLinkInfo && !lnk.ForceNoLinkInfo)
        {
            var (info, _) = ParseLinkInfo.Read(c, diag);
            lnk.LinkInfo = info;
        }

        ParseHeader.TryParseStrings(c, lnk);

        // ExtraData blocks run to a zero-size terminal block; anything after it
        // is overlay content (Unit42 execution category: overlay payloads).
        var (endPos, sawTerminal) = ParseBlocks.Walk(c, lnk, diag);

        if (!sawTerminal && c.Remaining >= 0)
        {
            // No explicit terminal marker: everything left is treated as overlay.
        }
        int overlayAt = sawTerminal ? c.Pos : endPos;
        if (overlayAt < data.Length)
        {
            lnk.Overlay = data[overlayAt..];
        }

        foreach (var d in c.Diag) diag.Add(d);
        foreach (var d in diag.Notes) if (!lnk.Diagnostics.Contains(d)) lnk.Diagnostics.Add(d);
        return lnk;
    }

    /// <summary>Human-facing summary of where the shortcut actually points.</summary>
    public static string ResolveTarget(LnkFile lnk)
    {
        var parts = new List<string>();
        if (lnk.LinkInfo?.LocalBasePath is string lbp && lbp.Length > 0) parts.Add(lbp);
        if (lnk.LinkInfo?.NetName is string nn && nn.Length > 0)
            parts.Add("\\\\" + nn + "\\" + (lnk.LinkInfo.CommonPathSuffix ?? ""));
        else if (lnk.LinkInfo?.CommonPathSuffix is string cps && cps.Length > 0 && parts.Count == 0)
            parts.Add(cps);
        if (lnk.EnvironmentTarget is string env && env.Length > 0) parts.Add(env);
        if (parts.Count == 0)
        {
            var idParts = lnk.TargetIdList
                .Where(i => !string.IsNullOrEmpty(i.Label) && i.Label != "root")
                .Select(i => i.Label);
            var joined = string.Join("\\", idParts);
            if (joined.Length > 0) parts.Add(joined);
        }
        if (parts.Count == 0) parts.Add("(none)");
        return string.Join(" | ", parts);
    }
}
