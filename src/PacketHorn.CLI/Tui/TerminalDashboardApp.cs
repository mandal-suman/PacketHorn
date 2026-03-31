using System.Data;
using System.Net;
using System.Net.NetworkInformation;
using System.Threading;
using PacketHorn.Capture.Common;
using PacketHorn.Capture.Windows;
using PacketHorn.Core.Configuration;
using PacketHorn.Core.Enums;
using PacketHorn.Core.Interfaces;
using PacketHorn.Core.Models;
using PacketHorn.Core.Pipeline;
using PacketHorn.Core.Utilities;
using PacketHorn.Detection.Engine;
using PacketHorn.Detection.Evaluators;
using PacketHorn.Detection.Rules;
using PacketHorn.Output.Logging;
using PacketHorn.Output.PCAP;
using PacketHorn.Output.Reports;
using PacketHorn.Processing.Builders;
using PacketHorn.Response.Decision;
using PacketHorn.Response.Engine;
using PacketHorn.Response.Firewall;
using SharpPcap;
using Terminal.Gui;

namespace PacketHorn.CLI.Tui;

public sealed class TerminalDashboardApp
{
    private readonly string _projectRoot;
    private readonly AppConfig _config;

    private readonly Dictionary<SeverityLevel, ulong> _severityCounts = new();
    private readonly Dictionary<string, ulong> _threatCounts = new(StringComparer.OrdinalIgnoreCase);

    private readonly DataTable _packetsTable = new("Packets");
    private readonly DataTable _detectionsTable = new("Detections");
    private readonly DataTable _eventsTable = new("Events");

    private List<ICaptureDevice> _devices = new();

    private DecisionMode _currentMode;
    private ulong _totalPackets;
    private ulong _totalBytes;
    private ulong _totalDetections;
    private DateTime _sessionStartUtc;

    private string _selectedInterfaceName = string.Empty;
    private string _selectedInterfaceDescription = string.Empty;

    private PacketPipeline? _pipeline;
    private PipelineCoordinator? _coordinator;
    private PcapWriter? _pcapWriter;
    private RuntimeFileLogger? _logger;
    private PdfReportGenerator? _reportGenerator;

    private bool _isRunning;

    private ListView? _interfaceList;
    private RadioGroup? _modeRadio;
    private TableView? _packetsView;
    private TableView? _detectionsView;
    private TableView? _eventsView;
    private Label? _statusLabel;
    private Label? _packetStat;
    private Label? _byteStat;
    private Label? _detectionStat;
    private Label? _hostIdentityLabel;
    private Label? _hostNetworkLabel;
    private Label? _hostInterfaceLabel;
    private Label? _hostOsLabel;

    public TerminalDashboardApp(string projectRoot, AppConfig config)
    {
        _projectRoot = projectRoot;
        _config = config;
        _currentMode = config.Detection.Mode;
        _sessionStartUtc = DateTime.UtcNow;

        ConfigureTables();
    }

    public void Run()
    {
        _devices = InterfaceEnumerator.GetDevices().ToList();
        if (_devices.Count == 0)
        {
            Console.WriteLine("No capture interfaces found. Ensure Npcap driver is installed and running.");
            return;
        }

        Application.Init();
        var top = Application.Top;

        var menu = new MenuBar(new[]
        {
            new MenuBarItem("_File", new[]
            {
                new MenuItem("_Start", "Start capture", StartCapture),
                new MenuItem("S_top", "Stop capture", StopCapture),
                new MenuItem("_Report", "Generate PDF report", GenerateReport),
                new MenuItem("_Quit", "Quit", () => Application.RequestStop())
            })
        });

        var win = new Window("PacketHorn - Windows NIDR")
        {
            X = 0,
            Y = 1,
            Width = Dim.Fill(),
            Height = Dim.Fill()
        };

        BuildControls(win);
        top.Add(menu, win);

        Application.Run();
        Cleanup();
    }

    private void ConfigureTables()
    {
        _packetsTable.Columns.Add("Time", typeof(string));
        _packetsTable.Columns.Add("Proto", typeof(string));
        _packetsTable.Columns.Add("Source", typeof(string));
        _packetsTable.Columns.Add("Destination", typeof(string));
        _packetsTable.Columns.Add("Bytes", typeof(string));
        _packetsTable.Columns.Add("Flags", typeof(string));

        _detectionsTable.Columns.Add("Time", typeof(string));
        _detectionsTable.Columns.Add("Severity", typeof(string));
        _detectionsTable.Columns.Add("Rule", typeof(string));
        _detectionsTable.Columns.Add("Source", typeof(string));
        _detectionsTable.Columns.Add("Destination", typeof(string));
        _detectionsTable.Columns.Add("Confidence", typeof(string));

        _eventsTable.Columns.Add("Time", typeof(string));
        _eventsTable.Columns.Add("Event", typeof(string));
    }

    private void BuildControls(Window win)
    {
        var interfaceFrame = new FrameView("Interface") { X = 0, Y = 0, Width = 45, Height = 7 };
        var modeFrame = new FrameView("Mode") { X = Pos.Right(interfaceFrame), Y = 0, Width = 26, Height = 7 };
        var actionFrame = new FrameView("Actions") { X = Pos.Right(modeFrame), Y = 0, Width = Dim.Fill(), Height = 7 };

        var ifaceItems = _devices.Select((d, i) => $"[{i}] {d.Description ?? d.Name}").ToList();
        _interfaceList = new ListView(ifaceItems)
        {
            X = 0,
            Y = 0,
            Width = Dim.Fill(),
            Height = Dim.Fill()
        };
        _interfaceList.SelectedItemChanged += _ => RefreshHostInfo();

        var initialIndex = ResolveInterfaceIndex(_config.Capture.Interface);
        _interfaceList.SelectedItem = Math.Max(0, initialIndex);
        interfaceFrame.Add(_interfaceList);

        _modeRadio = new RadioGroup(
            new Rect(0, 0, 28, 3),
            new NStack.ustring[] { "AlertOnly", "InteractiveBlock", "AutoBlock" },
            _currentMode switch
            {
                DecisionMode.AlertOnly => 0,
                DecisionMode.InteractiveBlock => 1,
                _ => 2
            });
        modeFrame.Add(_modeRadio);

        var startButton = new Button("Start") { X = 1, Y = 1 };
        startButton.Clicked += StartCapture;
        var stopButton = new Button("Stop") { X = Pos.Right(startButton) + 1, Y = 1 };
        stopButton.Clicked += StopCapture;
        var reportButton = new Button("Report") { X = Pos.Right(stopButton) + 1, Y = 1 };
        reportButton.Clicked += GenerateReport;

        var actionHelp = new Label(
            "Start/Stop controls capture. Report exports formal PDF.\n" +
            "Table navigation: Up/Down rows, Left/Right columns.")
        {
            X = 1,
            Y = 3,
            Width = Dim.Fill() - 2,
            Height = 2
        };

        actionFrame.Add(startButton, stopButton, reportButton, actionHelp);

        var statsFrame = new FrameView("Session and Host") { X = 0, Y = Pos.Bottom(interfaceFrame), Width = Dim.Fill(), Height = 5 };
        _statusLabel = new Label("Status: READY") { X = 1, Y = 0 };
        _packetStat = new Label("Packets: 0") { X = 24, Y = 0 };
        _byteStat = new Label("Bytes: 0") { X = 40, Y = 0 };
        _detectionStat = new Label("Detections: 0") { X = 60, Y = 0 };
        _hostIdentityLabel = new Label("Host: -  User: -  OS: -") { X = 1, Y = 1, Width = Dim.Fill() - 2 };
        _hostNetworkLabel = new Label("Primary IP: -  MAC: -") { X = 1, Y = 2, Width = Dim.Fill() - 2 };
        _hostInterfaceLabel = new Label("Capture Interface: -") { X = 1, Y = 3, Width = Dim.Fill() - 2 };
        _hostOsLabel = new Label(string.Empty) { X = 1, Y = 4, Width = 1, Height = 1, Visible = false };
        statsFrame.Add(_statusLabel, _packetStat, _byteStat, _detectionStat, _hostIdentityLabel, _hostNetworkLabel, _hostInterfaceLabel, _hostOsLabel);

        RefreshHostInfo();

        var packetFrame = new FrameView("Packets") { X = 0, Y = Pos.Bottom(statsFrame), Width = Dim.Percent(56), Height = Dim.Fill() - 5 };
        _packetsView = CreateTableView(_packetsTable);
        packetFrame.Add(_packetsView);

        var detectionFrame = new FrameView("Detections") { X = Pos.Right(packetFrame), Y = Pos.Bottom(statsFrame), Width = Dim.Fill(), Height = Dim.Percent(44) };
        _detectionsView = CreateTableView(_detectionsTable);
        detectionFrame.Add(_detectionsView);

        var eventsFrame = new FrameView("Events") { X = Pos.Right(packetFrame), Y = Pos.Bottom(detectionFrame), Width = Dim.Fill(), Height = Dim.Fill() };
        _eventsView = CreateTableView(_eventsTable);
        eventsFrame.Add(_eventsView);

        var statusBar = new StatusBar(new[]
        {
            new StatusItem(Key.F5, "~F5~ Start", StartCapture),
            new StatusItem(Key.F6, "~F6~ Stop", StopCapture),
            new StatusItem(Key.F7, "~F7~ Report", GenerateReport),
            new StatusItem(Key.F8, "~F8~ Toggle Mode", ToggleMode),
            new StatusItem(Key.Q | Key.CtrlMask, "~Ctrl-Q~ Quit", () => Application.RequestStop())
        });

        win.Add(interfaceFrame, modeFrame, actionFrame, statsFrame, packetFrame, detectionFrame, eventsFrame, statusBar);
    }

    private static TableView CreateTableView(DataTable table)
    {
        var view = new TableView
        {
            X = 0,
            Y = 0,
            Width = Dim.Fill(),
            Height = Dim.Fill(),
            FullRowSelect = true,
            MultiSelect = false,
            Table = table
        };

        view.Style.AlwaysShowHeaders = true;
        return view;
    }

    private void StartCapture()
    {
        if (_isRunning)
            return;

        try
        {
            var interfaceName = GetSelectedInterfaceName();
            _currentMode = GetSelectedMode();
            var selectedDevice = _devices.FirstOrDefault(d => d.Name.Equals(interfaceName, StringComparison.OrdinalIgnoreCase));
            _selectedInterfaceName = interfaceName;
            _selectedInterfaceDescription = selectedDevice?.Description ?? "n/a";
            RefreshHostInfo();

            var rulesDir = ResolvePath(_config.Paths.RulesDirectory);
            var logsDir = ResolvePath(_config.Paths.LogsDirectory);
            var pcapDir = ResolvePath(_config.Paths.PcapDirectory);
            var reportsDir = ResolvePath(_config.Paths.ReportsDirectory);

            Directory.CreateDirectory(rulesDir);
            Directory.CreateDirectory(logsDir);
            Directory.CreateDirectory(pcapDir);
            Directory.CreateDirectory(reportsDir);

            _logger = new RuntimeFileLogger(logsDir) { VerboseEnabled = true };
            _reportGenerator = new PdfReportGenerator();
            _pcapWriter = new PcapWriter(Path.Combine(pcapDir, $"capture_{DateTime.UtcNow:yyyyMMdd_HHmmss}.pcap"));

            var ruleLoader = new RuleLoader(rulesDir);
            var sigEval = new SignatureEvaluator(ruleLoader.LoadSignatureRules());
            var behEval = new BehaviorEvaluator(ruleLoader.LoadBehaviorRules());
            var ruleEngine = new RuleEngine(sigEval, behEval);

            IDecisionEngine decisionEngine = new DecisionEngine();
            IResponseEngine responseEngine = new WindowsResponseEngine(
                new WindowsFirewallController(),
                _config.Firewall.BlockDurationSeconds,
                RequestBlockApproval,
                msg => AppendEvent("RESPONSE", msg));

            var captureEngine = new WindowsCaptureEngine(
                interfaceName,
                _config.Capture.Promiscuous,
                _config.Capture.ReadTimeoutMs,
                _config.Capture.Filter);

            var packetBuilder = new StructuredPacketBuilder();
            var queue = new BufferQueue<RawPacket>(_config.Capture.BufferQueueSize);
            _pipeline = new PacketPipeline(captureEngine, queue, packetBuilder, ruleEngine);

            _pipeline.OnRawPacket += (_, e) =>
            {
                if (e.Packet == null)
                    return;

                _pcapWriter?.WritePacket(e.Packet);
                _totalPackets++;
                _totalBytes += (ulong)e.Packet.Length;
                AppendRawPacket(e.Packet);
                UpdateStats();
            };

            _pipeline.OnStructuredPacket += (_, e) =>
            {
                if (e.Packet == null)
                    return;

                AppendStructuredPacket(e.Packet);
            };

            _pipeline.OnDetection += (_, e) =>
            {
                if (e.Detection?.Result == null)
                    return;

                _totalDetections++;
                _severityCounts.TryGetValue(e.Detection.Result.SeverityLevel, out var sevCount);
                _severityCounts[e.Detection.Result.SeverityLevel] = sevCount + 1;
                _threatCounts.TryGetValue(e.Detection.Result.ThreatType, out var thCount);
                _threatCounts[e.Detection.Result.ThreatType] = thCount + 1;

                AppendDetection(e.Detection);

                var decision = decisionEngine.Evaluate(e.Detection.Result, _currentMode);
                responseEngine.ProcessDecision(decision, e.Detection.Result);
                UpdateStats();
            };

            _coordinator = new PipelineCoordinator(_pipeline);
            _coordinator.Start();
            _isRunning = true;
            _sessionStartUtc = DateTime.UtcNow;
            SetStatus("RUNNING");
            AppendEvent("INFO", $"Capture started on {_selectedInterfaceName} ({_selectedInterfaceDescription}). Mode={_currentMode}");
        }
        catch (Exception ex)
        {
            AppendEvent("ERROR", $"Start failed: {ex.Message}");
            SetStatus("ERROR");
        }
    }

    private void StopCapture()
    {
        if (!_isRunning)
            return;

        try
        {
            _coordinator?.Stop();
            _coordinator = null;
            _pipeline = null;
            _pcapWriter?.Dispose();
            _pcapWriter = null;
            _isRunning = false;
            SetStatus("STOPPED");
            AppendEvent("INFO", "Capture stopped.");
        }
        catch (Exception ex)
        {
            AppendEvent("ERROR", $"Stop error: {ex.Message}");
        }
    }

    private void GenerateReport()
    {
        try
        {
            if (_reportGenerator == null)
            {
                AppendEvent("WARN", "Report generator not initialized. Start capture first.");
                return;
            }

            var report = new ReportSummary
            {
                SessionStartUtc = _sessionStartUtc,
                SessionEndUtc = DateTime.UtcNow,
                TotalPackets = _totalPackets,
                TotalBytes = _totalBytes,
                TotalDetections = _totalDetections,
                DecisionMode = _currentMode,
                SeverityCounts = new Dictionary<SeverityLevel, ulong>(_severityCounts),
                ThreatCounts = new Dictionary<string, ulong>(_threatCounts, StringComparer.OrdinalIgnoreCase),
                HostName = Environment.MachineName,
                UserName = Environment.UserName,
                OSDescription = Environment.OSVersion.VersionString,
                LocalAddresses = GetLocalIPv4Addresses(),
                InterfaceName = _selectedInterfaceName,
                InterfaceDescription = _selectedInterfaceDescription,
                CaptureFilter = _config.Capture.Filter,
                Promiscuous = _config.Capture.Promiscuous,
                ReadTimeoutMs = _config.Capture.ReadTimeoutMs
            };

            var reportPath = _reportGenerator.Generate(report, ResolvePath(_config.Paths.ReportsDirectory));
            AppendEvent("INFO", $"Report generated: {reportPath}");
        }
        catch (Exception ex)
        {
            AppendEvent("ERROR", $"Report failed: {ex.Message}");
        }
    }

    private void ToggleMode()
    {
        _currentMode = _currentMode switch
        {
            DecisionMode.AlertOnly => DecisionMode.InteractiveBlock,
            DecisionMode.InteractiveBlock => DecisionMode.AutoBlock,
            _ => DecisionMode.AlertOnly
        };

        if (_modeRadio != null)
        {
            _modeRadio.SelectedItem = _currentMode switch
            {
                DecisionMode.AlertOnly => 0,
                DecisionMode.InteractiveBlock => 1,
                _ => 2
            };
        }

        AppendEvent("INFO", $"Mode changed to {_currentMode}");
    }

    private bool RequestBlockApproval(string ip, string reason)
    {
        var approved = false;
        using var wait = new ManualResetEventSlim(false);

        Application.MainLoop.Invoke(() =>
        {
            var answer = MessageBox.Query("Approve Block", $"Block IP {ip}?\n{reason}", "Approve", "Reject");
            approved = answer == 0;
            wait.Set();
        });

        wait.Wait();
        return approved;
    }

    private void SetStatus(string text)
    {
        Application.MainLoop.Invoke(() =>
        {
            if (_statusLabel != null)
                _statusLabel.Text = $"Status: {text}";
        });
    }

    private void UpdateStats()
    {
        Application.MainLoop.Invoke(() =>
        {
            if (_packetStat != null) _packetStat.Text = $"Packets: {_totalPackets}";
            if (_byteStat != null) _byteStat.Text = $"Bytes: {_totalBytes}";
            if (_detectionStat != null) _detectionStat.Text = $"Detections: {_totalDetections}";
        });
    }

    private void AppendRawPacket(RawPacket packet)
    {
        AddPacketRow(
            DateTime.Now.ToString("HH:mm:ss"),
            "RAW",
            "-",
            "-",
            packet.Length.ToString(),
            "-");
    }

    private void AppendStructuredPacket(StructuredPacket packet)
    {
        AddPacketRow(
            DateTime.Now.ToString("HH:mm:ss"),
            packet.Protocol.ToString(),
            Truncate($"{packet.SrcIP}:{packet.SrcPort}", 28),
            Truncate($"{packet.DstIP}:{packet.DstPort}", 28),
            packet.PacketSize.ToString(),
            Truncate(packet.Flags, 16));
    }

    private void AddPacketRow(string time, string proto, string source, string destination, string bytes, string flags)
    {
        Application.MainLoop.Invoke(() =>
        {
            _packetsTable.Rows.Add(time, proto, source, destination, bytes, flags);
            TrimTableRows(_packetsTable, _config.Ui.PacketListLimit);
            _packetsView?.SetNeedsDisplay();
        });
    }

    private void AppendDetection(DetectionMatch detection)
    {
        if (detection.Result == null)
            return;

        Application.MainLoop.Invoke(() =>
        {
            _detectionsTable.Rows.Add(
                DateTime.Now.ToString("HH:mm:ss"),
                detection.Result.SeverityLevel.ToString(),
                Truncate(detection.RuleName, 22),
                Truncate(detection.Result.SourceIP, 18),
                Truncate(detection.Result.DestinationIP, 18),
                detection.Result.ConfidenceScore.ToString("P0"));

            TrimTableRows(_detectionsTable, _config.Ui.DetectionListLimit);
            _detectionsView?.SetNeedsDisplay();
        });
    }

    private void AppendEvent(string level, string message)
    {
        Application.MainLoop.Invoke(() =>
        {
            _eventsTable.Rows.Add(DateTime.Now.ToString("HH:mm:ss"), $"{Truncate(level, 10)}: {message}");
            TrimTableRows(_eventsTable, 300);
            _eventsView?.SetNeedsDisplay();
        });
    }

    private static void TrimTableRows(DataTable table, int keepRows)
    {
        while (table.Rows.Count > keepRows)
            table.Rows.RemoveAt(0);
    }

    private void Cleanup()
    {
        StopCapture();
        _logger = null;
        Application.Shutdown();
    }

    private int ResolveInterfaceIndex(string configured)
    {
        if (string.IsNullOrWhiteSpace(configured) || configured.Equals("AUTO", StringComparison.OrdinalIgnoreCase))
        {
            if (_devices.Count == 0)
                return 0;

            var bestIndex = 0;
            var bestScore = int.MinValue;

            for (int i = 0; i < _devices.Count; i++)
            {
                var score = ScoreDevice(_devices[i]);
                if (score > bestScore)
                {
                    bestScore = score;
                    bestIndex = i;
                }
            }

            return bestIndex;
        }

        if (int.TryParse(configured, out var idx) && idx >= 0 && idx < _devices.Count)
            return idx;

        for (int i = 0; i < _devices.Count; i++)
        {
            var d = _devices[i];
            if (d.Name.Equals(configured, StringComparison.OrdinalIgnoreCase)
                || (d.Description?.Equals(configured, StringComparison.OrdinalIgnoreCase) ?? false)
                || d.Name.Contains(configured, StringComparison.OrdinalIgnoreCase)
                || (d.Description?.Contains(configured, StringComparison.OrdinalIgnoreCase) ?? false))
                return i;
        }

        return 0;
    }

    private static int ScoreDevice(ICaptureDevice device)
    {
        var text = $"{device.Name} {device.Description}".ToLowerInvariant();
        var score = 0;

        if (text.Contains("intel") || text.Contains("realtek") || text.Contains("ethernet") || text.Contains("wi-fi") || text.Contains("wireless"))
            score += 30;

        if (text.Contains("loopback"))
            score -= 100;

        if (text.Contains("wan miniport") || text.Contains("vmware") || text.Contains("virtual") || text.Contains("hyper-v"))
            score -= 40;

        return score;
    }

    private string GetSelectedInterfaceName()
    {
        if (_interfaceList == null || _devices.Count == 0)
            return _config.Capture.Interface;

        var idx = Math.Clamp(_interfaceList.SelectedItem, 0, _devices.Count - 1);
        return _devices[idx].Name;
    }

    private DecisionMode GetSelectedMode()
    {
        if (_modeRadio == null)
            return _currentMode;

        return _modeRadio.SelectedItem switch
        {
            0 => DecisionMode.AlertOnly,
            1 => DecisionMode.InteractiveBlock,
            _ => DecisionMode.AutoBlock
        };
    }

    private string ResolvePath(string configuredPath)
    {
        if (Path.IsPathRooted(configuredPath))
            return configuredPath;

        var normalized = configuredPath.Replace('/', Path.DirectorySeparatorChar);
        return Path.Combine(_projectRoot, normalized);
    }

    private static string Truncate(string value, int max)
    {
        if (string.IsNullOrEmpty(value))
            return "-";

        return value.Length <= max ? value : value[..(max - 1)];
    }

    private static List<string> GetLocalIPv4Addresses()
    {
        var ips = new List<string>();

        foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (ni.OperationalStatus != OperationalStatus.Up)
                continue;

            foreach (var ua in ni.GetIPProperties().UnicastAddresses)
            {
                if (ua.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork
                    && !IPAddress.IsLoopback(ua.Address))
                {
                    ips.Add($"{ni.Name}:{ua.Address}");
                }
            }
        }

        return ips.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    private void RefreshHostInfo()
    {
        var host = Environment.MachineName;
        var user = Environment.UserName;
        var os = Environment.OSVersion.VersionString;
        var interfaceDisplay = string.IsNullOrWhiteSpace(_selectedInterfaceName)
            ? (_devices.Count > 0 ? _devices[Math.Clamp(_interfaceList?.SelectedItem ?? 0, 0, _devices.Count - 1)].Name : "-")
            : _selectedInterfaceName;
        var interfaceDescription = string.IsNullOrWhiteSpace(_selectedInterfaceDescription) ? "n/a" : _selectedInterfaceDescription;

        var networkInfo = GetPrimaryNetworkInfo();
        var ip = string.IsNullOrWhiteSpace(networkInfo.IpAddress) ? "-" : networkInfo.IpAddress;
        var mac = string.IsNullOrWhiteSpace(networkInfo.MacAddress) ? "-" : networkInfo.MacAddress;

        if (Application.MainLoop != null)
        {
            Application.MainLoop.Invoke(() =>
            {
                if (_hostIdentityLabel != null)
                    _hostIdentityLabel.Text = Truncate($"Host: {host}  User: {user}  OS: {os}", 180);
                if (_hostNetworkLabel != null)
                    _hostNetworkLabel.Text = Truncate($"Primary IP: {ip}  MAC: {mac}", 140);
                if (_hostInterfaceLabel != null)
                    _hostInterfaceLabel.Text = Truncate($"Capture Interface: {interfaceDisplay} ({interfaceDescription})", 180);
            });
            return;
        }

        if (_hostIdentityLabel != null)
            _hostIdentityLabel.Text = Truncate($"Host: {host}  User: {user}  OS: {os}", 180);
        if (_hostNetworkLabel != null)
            _hostNetworkLabel.Text = Truncate($"Primary IP: {ip}  MAC: {mac}", 140);
        if (_hostInterfaceLabel != null)
            _hostInterfaceLabel.Text = Truncate($"Capture Interface: {interfaceDisplay} ({interfaceDescription})", 180);
    }

    private static (string IpAddress, string MacAddress) GetPrimaryNetworkInfo()
    {
        foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (ni.OperationalStatus != OperationalStatus.Up || ni.NetworkInterfaceType == NetworkInterfaceType.Loopback)
                continue;

            var ip = ni.GetIPProperties().UnicastAddresses
                .Select(ua => ua.Address)
                .FirstOrDefault(a => a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork && !IPAddress.IsLoopback(a));

            if (ip == null)
                continue;

            var macBytes = ni.GetPhysicalAddress().GetAddressBytes();
            var mac = macBytes.Length == 0
                ? string.Empty
                : string.Join(":", macBytes.Select(b => b.ToString("X2")));

            return (ip.ToString(), mac);
        }

        return (string.Empty, string.Empty);
    }
}
