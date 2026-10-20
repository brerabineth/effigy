namespace Effigy;

public sealed class RuleDef
{
    public required string Id;
    public required string Title;
    public required Severity Severity;
    public required int Weight;
    public required string Detail;
}

/// <summary>
/// Static rule catalog. Weights sum into the suite-wide verdict bands
/// (clean &lt;10, watch &lt;25, suspicious &lt;60, hostile &gt;=60).
/// Grounded in the documented LNK abuse patterns: in-argument scripts,
/// encoded payloads, icon masquerade, UNC staging, overlay execution.
/// </summary>
public static class Rules
{
    public static readonly RuleDef ArgsDecodedLolbin = new()
    {
        Id = "args.decoded.lolbin", Title = "Encoded payload decodes to a LOLBin command",
        Severity = Severity.Critical, Weight = 50,
        Detail = "An embedded base64/hex payload in the arguments decodes to shell/LOLBin content",
    };
    public static readonly RuleDef ArgsIexCradle = new()
    {
        Id = "args.iex.cradle", Title = "Download cradle inside arguments",
        Severity = Severity.Critical, Weight = 45,
        Detail = "IEX/Invoke-Expression plus Download*/WebClient markers — fetch-and-run pattern",
    };
    public static readonly RuleDef ArgsXorDecoder = new()
    {
        Id = "args.payload.xor-decoder", Title = "Decoder loop with XOR key inside arguments",
        Severity = Severity.Critical, Weight = 45,
        Detail = "Argument text contains a decode loop with an XOR key — the 2026 DPRK LNK pattern",
    };
    public static readonly RuleDef OverlayScript = new()
    {
        Id = "overlay.script", Title = "Overlay after terminal block contains script content",
        Severity = Severity.Critical, Weight = 40,
        Detail = "Bytes appended past the ExtraData terminal block look like executable script",
    };
    public static readonly RuleDef ArgsEncodedSwitch = new()
    {
        Id = "args.lolbin.encoded-switch", Title = "Encoded command switch (-enc / -EncodedCommand)",
        Severity = Severity.High, Weight = 30,
        Detail = "Arguments invoke a shell with an encoded-command switch",
    };
    public static readonly RuleDef ArgsHiddenWindow = new()
    {
        Id = "args.lolbin.hidden-window", Title = "Hidden-window switch in arguments",
        Severity = Severity.High, Weight = 30,
        Detail = "Arguments suppress the visible window (-w hidden / WindowStyle Hidden)",
    };
    public static readonly RuleDef SpoofDocumentName = new()
    {
        Id = "spoof.document-name", Title = "Display name poses as a document while target is a script host",
        Severity = Severity.High, Weight = 30,
        Detail = "Shortcut name/path suggests a document but the resolved target is a LOLBin",
    };
    public static readonly RuleDef TargetStartup = new()
    {
        Id = "target.startup", Title = "Shortcut points into a Startup folder",
        Severity = Severity.High, Weight = 30,
        Detail = "Special/known-folder reference resolves to Startup — persistence placement",
    };
    public static readonly RuleDef TargetLolbin = new()
    {
        Id = "target.lolbin", Title = "Resolved target is a LOLBin/script host",
        Severity = Severity.High, Weight = 25,
        Detail = "Target binary is cmd/powershell/mshta/rundll32/wscript or friends",
    };
    public static readonly RuleDef IconDocument = new()
    {
        Id = "icon.document", Title = "Icon masquerades as a document",
        Severity = Severity.High, Weight = 20,
        Detail = "Icon location references a document-typed file or shell resource commonly abused",
    };
    public static readonly RuleDef ArgsLolbin = new()
    {
        Id = "args.lolbin.generic", Title = "LOLBin invocation inside arguments",
        Severity = Severity.High, Weight = 20,
        Detail = "Arguments chain another LOLBin invocation",
    };
    public static readonly RuleDef IconRemote = new()
    {
        Id = "icon.remote", Title = "Icon fetched from remote share/URL",
        Severity = Severity.Medium, Weight = 20,
        Detail = "Icon location is a UNC path or URL",
    };
    public static readonly RuleDef EncodedBase64 = new()
    {
        Id = "encoded.base64-blob", Title = "Base64 blob inside free text",
        Severity = Severity.Medium, Weight = 18,
        Detail = "A long base64 run is present (decoding covered by its own rule)",
    };
    public static readonly RuleDef EncodedHex = new()
    {
        Id = "encoded.hex-blob", Title = "Hex blob inside free text",
        Severity = Severity.Medium, Weight = 18,
        Detail = "A long hex run is present",
    };
    public static readonly RuleDef ArgsRemotePayload = new()
    {
        Id = "args.http.remote-payload", Title = "URL inside arguments",
        Severity = Severity.Medium, Weight = 18,
        Detail = "Arguments reference an http/ftp URL",
    };
    public static readonly RuleDef TargetRemote = new()
    {
        Id = "target.remote", Title = "Target resolves to a network share",
        Severity = Severity.Medium, Weight = 15,
        Detail = "LinkInfo/IDList points at a UNC path",
    };
    public static readonly RuleDef IconMismatch = new()
    {
        Id = "icon.mismatch", Title = "Icon does not match the target binary",
        Severity = Severity.Medium, Weight = 15,
        Detail = "Icon points at a different application than the resolved target",
    };
    public static readonly RuleDef EnvVarExec = new()
    {
        Id = "env.var.exec", Title = "Execution path routed through environment variables",
        Severity = Severity.Medium, Weight = 15,
        Detail = "%TEMP%/%APPDATA%-style variables hide the real executable location",
    };
    public static readonly RuleDef TimestampsZeroed = new()
    {
        Id = "timestamps.zeroed", Title = "All FILETIME timestamps are zero",
        Severity = Severity.Medium, Weight = 12,
        Detail = "Creation/Access/Write times zeroed — forensic wipe behavior",
    };
    public static readonly RuleDef DarwinMsi = new()
    {
        Id = "darwin.msi", Title = "Darwin (MSI advertisement) block present",
        Severity = Severity.Medium, Weight = 12,
        Detail = "Shortcut advertises an MSI package identifier",
    };
    public static readonly RuleDef ArgsUnc = new()
    {
        Id = "args.unc", Title = "UNC path inside arguments",
        Severity = Severity.Medium, Weight = 12,
        Detail = "Arguments reference a \\\\host\\share path",
    };
    public static readonly RuleDef ArgsCmdChain = new()
    {
        Id = "args.cmd.chain", Title = "cmd.exe chain in arguments",
        Severity = Severity.Medium, Weight = 10,
        Detail = "Arguments wrap execution in cmd /c or chained commands",
    };
    public static readonly RuleDef ShowCommandHidden = new()
    {
        Id = "showcommand.minnoactive", Title = "Window shown minimized without activation",
        Severity = Severity.Low, Weight = 10,
        Detail = "ShowCommand is SW_SHOWMINNOACTIVE — typical for silent droppers",
    };
    public static readonly RuleDef ArgLengthExtreme = new()
    {
        Id = "arg.length.extreme", Title = "Unusually long command-line arguments",
        Severity = Severity.Low, Weight = 8,
        Detail = "Arguments exceed 400 characters",
    };
    public static readonly RuleDef StructureTruncated = new()
    {
        Id = "structure.truncated", Title = "Structure is truncated or malformed",
        Severity = Severity.Low, Weight = 10,
        Detail = "Parser hit end-of-structure early — damaged or anti-analysis file",
    };
    public static readonly RuleDef OverlayPresent = new()
    {
        Id = "overlay.present", Title = "Overlay data after terminal block",
        Severity = Severity.Info, Weight = 5,
        Detail = "Appended bytes exist past the ExtraData terminal marker",
    };
    public static readonly RuleDef TrackerMachineId = new()
    {
        Id = "tracker.machine-id", Title = "Tracker block exposes source machine identity",
        Severity = Severity.Info, Weight = 5,
        Detail = "MachineID/droid GUIDs available — attribution value, common in benign files too",
    };
    public static readonly RuleDef HeaderClsidUnknown = new()
    {
        Id = "header.clsid-unknown", Title = "Header CLSID is not the ShellLink CLSID",
        Severity = Severity.Low, Weight = 10,
        Detail = "File claims a different object class — not a standard shortcut",
    };
    public static readonly RuleDef StructureUnknownBlock = new()
    {
        Id = "structure.unknown-block", Title = "Unknown ExtraData block signature",
        Severity = Severity.Info, Weight = 5,
        Detail = "Extra block with unrecognized signature present",
    };

    public static readonly RuleDef[] All =
    {
        ArgsDecodedLolbin, ArgsIexCradle, ArgsXorDecoder, OverlayScript,
        ArgsEncodedSwitch, ArgsHiddenWindow, SpoofDocumentName, TargetStartup,
        TargetLolbin, IconDocument, ArgsLolbin, IconRemote,
        EncodedBase64, EncodedHex, ArgsRemotePayload, TargetRemote,
        IconMismatch, EnvVarExec, TimestampsZeroed, DarwinMsi, ArgsUnc,
        ArgsCmdChain, ShowCommandHidden, ArgLengthExtreme, StructureTruncated,
        OverlayPresent, TrackerMachineId, HeaderClsidUnknown, StructureUnknownBlock,
    };

    public static RuleDef? ById(string id)
    {
        foreach (var r in All) if (r.Id == id) return r;
        return null;
    }
}
