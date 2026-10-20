using System.Text.Json;

namespace Effigy;

public enum Severity { Info = 0, Low = 1, Medium = 2, High = 3, Critical = 4 }

public enum Band { Clean = 0, Watch = 1, Suspicious = 2, Hostile = 3 }

public sealed class Finding
{
    public required string Id { get; init; }
    public required Severity Severity { get; init; }
    public required int Weight { get; init; }
    public required string Detail { get; init; }
    public required string Source { get; init; }
}

public sealed class Diagnostics
{
    public List<string> Notes { get; } = new();
    public void Add(string m) { if (Notes.Count < 64) Notes.Add(m); }
}

/// <summary>Everything the parser can pull out of one .lnk file.</summary>
public sealed class LnkFile
{
    // Header
    public bool HasValidHeaderClsid;
    public uint LinkFlagsRaw;
    public uint FileAttributesRaw;
    public ulong CreationTime;
    public ulong AccessTime;
    public ulong WriteTime;
    public uint FileSize;
    public int IconIndex;
    public uint ShowCommand;
    public ushort HotKey;

    public bool HasTargetIdList;   // 0x1
    public bool HasLinkInfo;       // 0x2
    public bool HasName;           // 0x4
    public bool HasRelativePath;   // 0x8
    public bool HasWorkingDir;     // 0x10
    public bool HasArguments;      // 0x20
    public bool HasIconLocation;   // 0x40
    public bool IsUnicode;         // 0x80
    public bool ForceNoLinkInfo;   // 0x100
    public bool HasExpString;      // 0x200
    public bool RunInSeparateProcess; // 0x400
    public bool HasDarwinId;       // 0x1000
    public bool RunAsUser;         // 0x2000
    public bool HasExpIcon;        // 0x4000
    public bool NoPidlAlias;       // 0x8000
    public bool RunWithShimLayer;  // 0x20000
    public bool ForceNoLinkTrack;  // 0x40000
    public bool EnableTargetMetadata;  // 0x80000
    public bool DisableLinkPathTracking; // 0x100000
    public bool DisableKnownFolderTracking; // 0x200000
    public bool PreferEnvironmentPath; // 0x2000000
    public bool KeepLocalIdListForUncTarget; // 0x4000000

    // String data
    public string? NameLabel;
    public string? RelativePath;
    public string? WorkingDir;
    public string? Arguments;
    public string? IconLocation;

    // Structures
    public List<ShellItem> TargetIdList = new();
    public List<ShellItem> VistaIdList = new();
    public LinkInfoData? LinkInfo;
    public List<ExtraBlock> ExtraBlocks = new();
    public byte[]? Overlay;               // bytes after the terminal block
    public string? EnvironmentTarget;     // environment variable block target
    public TrackerData? Tracker;
    public uint? SpecialFolderId;
    public Guid? KnownFolderId;
    public string? DarwinId;
    public string? ShimLayer;
    public int ConsoleFeCodePage;
    public List<PropStoreEntry> PropertyStore = new();

    // Parse diagnostics
    public List<string> Diagnostics = new();
    public bool Truncated;
    public long SourceBytes;
}

public sealed class ShellItem
{
    public int Size;
    public byte Kind;
    public string? Label;      // friendly representation
    public string? RootGuid;   // for 0x1F root items
    public string? Drive;      // for drive items
    public bool IsNetwork;
    public bool IsUri;
    public string? Uri;
    public uint? FileSize;     // for file items
    public string? FatDate;    // for file items with timestamps
}

public sealed class LinkInfoData
{
    public uint VolumeDriveType;
    public uint VolumeSerial;
    public string? VolumeLabel;
    public string? LocalBasePath;
    public string? NetName;
    public string? NetDevice;
    public string? CommonPathSuffix;
    public bool HasLocalVolume;
    public bool HasCommonNetworkLink;
}

public sealed class TrackerData
{
    public uint Version;
    public Guid MachineId;
    public Guid DroidVolume;
    public Guid DroidFile;
    public Guid DroidBirthVolume;
    public Guid DroidBirthFile;
}

public sealed class PropStoreEntry
{
    public Guid FormatId;
    public uint PropertyId;
    public ushort ValueType;
    public string? StrValue;
    public uint? IntValue;
}

public abstract class ExtraBlock
{
    public uint Signature;
    public uint Size;
    public int Offset;
    public string DisplayName => ParseBlocks.NameOf(Signature);
}

public sealed class GenericBlock : ExtraBlock
{
    public byte[] Data = Array.Empty<byte>();
}

/// <summary>Verdict computed over the finding set.</summary>
public static class Verdict
{
    // Bands shared across the brerabin suite: clean <10, watch <25, suspicious <60, hostile >=60.
    public const int WatchAt = 10, SuspiciousAt = 25, HostileAt = 60;

    public static Band BandFor(int score) =>
        score >= HostileAt ? Band.Hostile :
        score >= SuspiciousAt ? Band.Suspicious :
        score >= WatchAt ? Band.Watch : Band.Clean;

    public static int ExitFor(Band b) => b switch
    {
        Band.Clean => 0,
        Band.Watch => 1,
        Band.Suspicious => 3,
        _ => 10,
    };

    public static string Name(Band b) => b switch
    {
        Band.Clean => "clean",
        Band.Watch => "watch",
        Band.Suspicious => "suspicious",
        _ => "hostile",
    };

    public static bool BandAtLeast(Band b, string gate) => gate.ToLowerInvariant() switch
    {
        "clean" => true,
        "watch" => b >= Band.Watch,
        "suspicious" => b >= Band.Suspicious,
        "hostile" => b >= Band.Hostile,
        _ => false,
    };

    public static Band Parse(string gate) => gate.ToLowerInvariant() switch
    {
        "clean" => Band.Clean,
        "watch" => Band.Watch,
        "suspicious" => Band.Suspicious,
        "hostile" => Band.Hostile,
        _ => throw new ArgumentException($"unknown band '{gate}'"),
    };

    /// <summary>Canonical single-line JSON for one verdict+findings pair.</summary>
    public static string ToJson(string path, Band band, int score, IReadOnlyList<Finding> findings,
        IReadOnlyList<string> diagnostics, long bytes)
    {
        using var ms = new MemoryStream();
        using (var w = new Utf8JsonWriter(ms, new JsonWriterOptions()))
        {
            w.WriteStartObject();
            w.WriteString("tool", "effigy");
            w.WriteString("version", Cli.Version);
            w.WriteString("file", path.Replace('\\', '/'));
            w.WriteNumber("bytes", bytes);
            w.WriteString("verdict", Name(band));
            w.WriteNumber("score", score);
            w.WriteStartArray("findings");
            foreach (var f in findings)
            {
                w.WriteStartObject();
                w.WriteString("id", f.Id);
                w.WriteString("severity", f.Severity.ToString().ToLowerInvariant());
                w.WriteNumber("weight", f.Weight);
                w.WriteString("source", f.Source);
                w.WriteString("detail", f.Detail);
                w.WriteEndObject();
            }
            w.WriteEndArray();
            w.WriteStartArray("diagnostics");
            foreach (var d in diagnostics) w.WriteStringValue(d);
            w.WriteEndArray();
            w.WriteEndObject();
        }
        return System.Text.Encoding.UTF8.GetString(ms.ToArray());
    }
}
