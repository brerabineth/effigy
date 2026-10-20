namespace Effigy;

public static class Cli
{
    public const string Version = "0.1.0";

    public static int Main(string[] argv)
    {
        Console.OutputEncoding = System.Text.Encoding.UTF8;
        try
        {
            return Dispatch(argv);
        }
        catch (UsageError e)
        {
            Console.Error.WriteLine($"effigy: {e.Message}");
            return 2;
        }
        catch (Exception e)
        {
            Console.Error.WriteLine($"effigy: internal error: {e.GetType().Name}: {e.Message}");
            return 2;
        }
    }

    private sealed class UsageError : Exception
    {
        public UsageError(string m) : base(m) { }
    }

    private static void Banner()
    {
        Console.Error.WriteLine(@"       __  __ _
  ___ / _|/ _(_) __ _ _   _
 / _ \ |_| |_| |/ _` | | | |
|  __/  _|  _| | (_| | |_| |
 \___|_| |_| |_|\__, |\__, |
                |___/ |___/
");
        Console.Error.WriteLine($"  effigy v{Version} - windows shortcut (.lnk) triage - offline, stdlib-only");
        Console.Error.WriteLine();
    }

    private static int Dispatch(string[] argv)
    {
        if (argv.Length == 0) { Usage(); return 2; }
        var cmd = argv[0];
        var rest = argv.Skip(1).ToArray();

        bool noColorFlag = rest.Contains("--no-color", StringComparer.Ordinal);
        string? noColorEnv = Environment.GetEnvironmentVariable("NO_COLOR");
        Report.SetColor(!noColorFlag && noColorEnv is null);

        switch (cmd)
        {
            case "scan": return CmdScan(rest);
            case "show": return CmdShow(rest);
            case "forge": return CmdForge(rest);
            case "rules": return CmdRules(rest);
            case "selftest": return Selftest.Run();
            case "help": case "--help": case "-h": Usage(); return 0;
            default:
                throw new UsageError($"unknown command '{cmd}' (try scan|show|forge|rules|selftest|help)");
        }
    }

    private sealed class FlagsResult
    {
        public bool Json, Md, NoBanner;
        public int MinScore;
        public string? FailOn;
        public List<string> Targets = new();
    }

    private static FlagsResult Flags(string[] argv)
    {
        var r = new FlagsResult();
        for (int i = 0; i < argv.Length; i++)
        {
            switch (argv[i])
            {
                case "--json": r.Json = true; break;
                case "--md": r.Md = true; break;
                case "--quiet": r.NoBanner = true; break;
                case "--no-color": break;
                case "--color": Report.SetColor(true); break;
                case "--min-score": r.MinScore = int.Parse(argv[++i]); break;
                case "--fail-on": r.FailOn = argv[++i]; break;
                default:
                    if (argv[i].StartsWith("--min-score=", StringComparison.Ordinal)) r.MinScore = int.Parse(argv[i]["--min-score=".Length..]);
                    else if (argv[i].StartsWith("--fail-on=", StringComparison.Ordinal)) r.FailOn = argv[i]["--fail-on=".Length..];
                    else r.Targets.Add(argv[i]);
                    break;
            }
        }
        return r;
    }

    private static int CmdScan(string[] argv)
    {
        var fl = Flags(argv);
        var results = new List<(string, Engine.Result)>();
        if (fl.Targets.Count == 0 || fl.Targets.SequenceEqual(new[] { "-" }))
        {
            // read stdin ('-' supported too)
            using var stdin = Console.OpenStandardInput();
            using var ms = new MemoryStream();
            stdin.CopyTo(ms);
            var bytes = ms.ToArray();
            var r = AnalyzeBytes(bytes, "-");
            return FinishScan(new List<(string, Engine.Result)> { ("-", r) }, fl);
        }
        foreach (var t in fl.Targets)
        {
            if (t == "-")
            {
                using var stdin = Console.OpenStandardInput();
                using var ms = new MemoryStream();
                stdin.CopyTo(ms);
                results.Add(("-", AnalyzeBytes(ms.ToArray(), "-")));
            }
            else if (Directory.Exists(t))
            {
                foreach (var f in Directory.EnumerateFiles(t, "*.lnk", SearchOption.AllDirectories).OrderBy(x => x, StringComparer.Ordinal))
                {
                    var bytes = File.ReadAllBytes(f);
                    results.Add((f, AnalyzeBytes(bytes, f)));
                }
            }
            else if (File.Exists(t))
            {
                var bytes = File.ReadAllBytes(t);
                results.Add((t, AnalyzeBytes(bytes, t)));
            }
            else
            {
                throw new UsageError($"no such file or directory: {t}");
            }
        }
        return FinishScan(results, fl);
    }

    private static Engine.Result AnalyzeBytes(byte[] bytes, string displayPath)
    {
        var diag = new Diagnostics();
        try
        {
            return Engine.Analyze(bytes, displayPath, diag);
        }
        catch (Exception)
        {
            // Parser defense-in-depth: a hostile file must degrade to a finding,
            // never crash the tool.
            var lnk = new LnkFile { SourceBytes = bytes.Length, Truncated = true };
            var f = new List<Finding>
            {
                new() { Id = Rules.StructureTruncated.Id, Severity = Rules.StructureTruncated.Severity,
                        Weight = Rules.StructureTruncated.Weight, Source = "parser", Detail = "analysis aborted on malformed input" },
            };
            int score = f[0].Weight;
            return new Engine.Result { Lnk = lnk, Findings = f, Score = score, Band = Verdict.BandFor(score) };
        }
    }

    private static int FinishScan(List<(string, Engine.Result)> results, FlagsResult fl)
    {
        if (fl.Json)
        {
            Console.Out.WriteLine(Report.JsonBundle(results));
        }
        else if (fl.Md)
        {
            if (!fl.NoBanner) Banner();
            Console.Out.WriteLine("# effigy triage");
            Console.Out.WriteLine();
            foreach (var (path, r) in results)
            {
                Console.Out.WriteLine(Report.Markdown(path, r));
                Console.Out.WriteLine();
            }
        }
        else
        {
            if (!fl.NoBanner) Banner();
            foreach (var (path, r) in results)
            {
                Console.Out.WriteLine(Report.Terminal(r, path));
                Console.Out.WriteLine();
            }
            if (results.Count > 1)
            {
                var worst = results.Max(x => x.Item2.Band);
                int total = results.Count;
                int hits = results.Count(x => x.Item2.Band >= Band.Watch);
                Console.Out.WriteLine($"  summary   {total} files, {hits} flagged, worst " + Report.BandColor(worst));
                Console.Out.WriteLine();
            }
        }

        int exit = 0;
        if (results.Count > 0)
        {
            var worst = results.Max(x => x.Item2.Band);
            exit = Verdict.ExitFor(worst);
        }
        if (fl.MinScore > 0)
        {
            int max = results.Count == 0 ? 0 : results.Max(x => x.Item2.Score);
            if (max < fl.MinScore) exit = 2; // threshold not met: usage-style failure
        }
        if (fl.FailOn is string gate && results.Count > 0)
        {
            var worst = results.Max(x => x.Item2.Band);
            if (Verdict.BandAtLeast(worst, gate)) exit = Math.Max(exit, 10);
        }
        return exit;
    }

    private static int CmdShow(string[] argv)
    {
        var paths = argv.Where(a => !a.StartsWith("--", StringComparison.Ordinal)).ToList();
        if (paths.Count == 0) throw new UsageError("show: provide at least one file");
        foreach (var p in paths)
        {
            if (!File.Exists(p)) throw new UsageError($"no such file: {p}");
            var diag = new Diagnostics();
            var lnk = LnkParser.Parse(File.ReadAllBytes(p), diag);
            Console.Out.WriteLine(Report.Show(lnk, p));
            Console.Out.WriteLine();
        }
        return 0;
    }

    private static int CmdForge(string[] argv)
    {
        var rest = argv.Where(a => !a.StartsWith("--", StringComparison.Ordinal)).ToList();
        string outDir = rest.Count > 0 ? rest[0] : "fixtures";
        Directory.CreateDirectory(outDir);
        foreach (var (name, bytes) in Forge.AllFixtures())
        {
            string path = Path.Combine(outDir, name);
            File.WriteAllBytes(path, bytes);
            Console.Out.WriteLine($"  {name,-22} {bytes.Length,5} bytes");
        }
        return 0;
    }

    private static int CmdRules(string[] argv)
    {
        bool json = argv.Contains("--json", StringComparer.Ordinal);
        if (json)
        {
            var lines = new List<string>();
            foreach (var r in Rules.All)
                lines.Add($"  {{\"id\":\"{r.Id}\",\"severity\":\"{r.Severity.ToString().ToLowerInvariant()}\",\"weight\":{r.Weight}}}");
            Console.Out.WriteLine("[\n" + string.Join(",\n", lines) + "\n]");
            return 0;
        }
        Banner();
        Console.Out.WriteLine($"  {Rules.All.Length} rules, bands: clean <{Verdict.WatchAt}  watch <{Verdict.SuspiciousAt}  suspicious <{Verdict.HostileAt}  hostile >= {Verdict.HostileAt}");
        Console.Out.WriteLine();
        foreach (var sev in new[] { Severity.Critical, Severity.High, Severity.Medium, Severity.Low, Severity.Info })
        {
            foreach (var r in Rules.All.Where(r => r.Severity == sev))
                Console.Out.WriteLine($"  {r.Severity.ToString().ToLowerInvariant(),-8} {r.Weight,3}  {r.Id,-28} {r.Title}");
        }
        return 0;
    }

    private static void Usage()
    {
        Banner();
        Console.Error.WriteLine("  scan [paths...]   triage .lnk files (file, directory, or '-' for stdin)");
        Console.Error.WriteLine("    --json            canonical single-line JSON");
        Console.Error.WriteLine("    --md              markdown report");
        Console.Error.WriteLine("    --quiet           suppress banner");
        Console.Error.WriteLine("    --min-score N     exit 2 unless a file scores >= N");
        Console.Error.WriteLine("    --fail-on BAND    exit 10 when worst verdict >= clean|watch|suspicious|hostile");
        Console.Error.WriteLine("  show paths...     deep forensic dump: blocks, droids, overlay");
        Console.Error.WriteLine("  forge [dir]       write the deterministic fixture set (default ./fixtures)");
        Console.Error.WriteLine("  rules [--json]    print the rule catalog and verdict bands");
        Console.Error.WriteLine("  selftest          run the unit test battery");
        Console.Error.WriteLine();
        Console.Error.WriteLine("  exits: 0 clean | 1 watch | 3 suspicious | 10 hostile | 2 usage/error");
    }
}
