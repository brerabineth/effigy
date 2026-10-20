namespace Effigy;

/// <summary>LinkInfo section — [MS-SHLLINK] 2.3 (local volume and/or network link).</summary>
public static class ParseLinkInfo
{
    public const uint VolIdAndLocalBasePath = 0x1;
    public const uint CommonNetworkRelLinkAndPathSuffix = 0x2;

    public static (LinkInfoData? info, bool ok) Read(Cursor c, Diagnostics diag)
    {
        if (!c.TryReadU32(out uint totalSize)) { diag.Add("linkinfo: size missing"); return (null, false); }
        if (totalSize < 0x1C || totalSize > c.Remaining + 4)
        {
            diag.Add($"linkinfo: implausible size 0x{totalSize:X}");
            return (null, false);
        }
        int end = c.Pos - 4 + (int)totalSize;

        if (!c.TryReadU32(out uint headerSize)) return (null, false);
        if (!c.TryReadU32(out uint flags)) return (null, false);

        var info = new LinkInfoData
        {
            HasLocalVolume = (flags & VolIdAndLocalBasePath) != 0,
            HasCommonNetworkLink = (flags & CommonNetworkRelLinkAndPathSuffix) != 0,
        };

        if (!c.TryReadU32(out uint volumeIdOff)) return (null, false);
        if (!c.TryReadU32(out uint localBasePathOff)) return (null, false);
        if (!c.TryReadU32(out uint commonNetRelLinkOff)) return (null, false);
        if (!c.TryReadU32(out uint commonPathSuffixOff)) return (null, false);

        int basePos = end - (int)totalSize; // absolute position of the LinkInfo block

        if (info.HasLocalVolume && volumeIdOff != 0)
            ReadVolumeId(c, basePos + (int)volumeIdOff, info, diag);
        if (info.HasLocalVolume && localBasePathOff != 0)
        {
            c.Seek(basePos + (int)localBasePathOff);
            info.LocalBasePath = ParseItems.ReadAnsiZ(c, Math.Min(1024, c.Remaining));
        }
        if (info.HasCommonNetworkLink && commonNetRelLinkOff != 0)
            ReadNetworkLink(c, basePos + (int)commonNetRelLinkOff, info, diag);
        if (commonPathSuffixOff != 0)
        {
            c.Seek(basePos + (int)commonPathSuffixOff);
            info.CommonPathSuffix = ParseItems.ReadAnsiZ(c, Math.Min(1024, c.Remaining));
        }

        bool ok = c.Seek(Math.Min(end, c.Pos));
        return (info, ok);
    }

    private static void ReadVolumeId(Cursor c, int at, LinkInfoData info, Diagnostics diag)
    {
        if (!c.Seek(at)) { diag.Add("linkinfo: volume offset out of range"); return; }
        if (!c.TryReadU32(out uint volSize)) return;
        if (!c.TryReadU32(out uint driveType)) return;
        if (!c.TryReadU32(out uint serial)) return;
        info.VolumeDriveType = driveType;
        info.VolumeSerial = serial;
        // 3 = fixed disk, 4 = remote drive (no serial), per spec table.
        if (driveType != 4) c.TrySkip(4); // drive serial is u32 in spec variants
        info.VolumeLabel = ParseItems.ReadAnsiZ(c, Math.Min(64, c.Remaining));
    }

    private static void ReadNetworkLink(Cursor c, int at, LinkInfoData info, Diagnostics diag)
    {
        if (!c.Seek(at)) { diag.Add("linkinfo: network offset out of range"); return; }
        if (!c.TryReadU32(out uint netSize)) return;
        if (!c.TryReadU32(out uint netFlags)) return;
        if (!c.TryReadU32(out uint netNameOff)) return;
        if (!c.TryReadU32(out uint deviceNameOff)) return;
        if (!c.TryReadU32(out uint providerType)) return;

        int basePos = at;
        if ((netFlags & 0x1) != 0 && netNameOff != 0)
        {
            c.Seek(basePos + (int)netNameOff);
            info.NetName = ParseItems.ReadAnsiZ(c, Math.Min(256, c.Remaining));
        }
        if ((netFlags & 0x2) != 0 && deviceNameOff != 0)
        {
            c.Seek(basePos + (int)deviceNameOff);
            info.NetDevice = ParseItems.ReadAnsiZ(c, Math.Min(256, c.Remaining));
        }
    }
}
