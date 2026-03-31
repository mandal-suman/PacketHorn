using QuestPDF;
using QuestPDF.Fluent;
using QuestPDF.Helpers;
using QuestPDF.Infrastructure;

namespace PacketHorn.Output.Reports;

public sealed class PdfReportGenerator
{
    public string Generate(ReportSummary summary, string reportsDirectory)
    {
        Settings.License = LicenseType.Community;

        Directory.CreateDirectory(reportsDirectory);
        var filePath = Path.Combine(reportsDirectory, $"PacketHorn_Report_{DateTime.UtcNow:yyyyMMdd_HHmmss}.pdf");

        Document.Create(container =>
        {
            container.Page(page =>
            {
                page.Size(PageSizes.A4);
                page.Margin(24);
                page.DefaultTextStyle(x => x.FontSize(10));

                page.Header().Element(BuildHeader(summary));

                page.Content().Column(column =>
                {
                    column.Spacing(8);

                    column.Item().Element(SectionCard).Column(c =>
                    {
                        c.Spacing(4);
                        c.Item().Text("1. Executive Summary").SemiBold().FontSize(12);
                        c.Item().Table(table =>
                        {
                            table.ColumnsDefinition(cols =>
                            {
                                cols.ConstantColumn(140);
                                cols.RelativeColumn();
                                cols.ConstantColumn(140);
                                cols.RelativeColumn();
                            });

                            AddKeyValueRow(table, "Session Start (UTC)", summary.SessionStartUtc.ToString("yyyy-MM-dd HH:mm:ss"), "Session End (UTC)", summary.SessionEndUtc.ToString("yyyy-MM-dd HH:mm:ss"));
                            AddKeyValueRow(table, "Decision Mode", summary.DecisionMode.ToString(), "Total Detections", summary.TotalDetections.ToString("N0"));
                            AddKeyValueRow(table, "Total Packets", summary.TotalPackets.ToString("N0"), "Total Bytes", summary.TotalBytes.ToString("N0"));
                        });
                    });

                    column.Item().Element(SectionCard).Column(c =>
                    {
                        c.Spacing(4);
                        c.Item().Text("2. Host and Environment").SemiBold().FontSize(12);
                        c.Item().Table(table =>
                        {
                            table.ColumnsDefinition(cols =>
                            {
                                cols.ConstantColumn(140);
                                cols.RelativeColumn();
                            });

                            AddKeyValueRow(table, "Host Name", summary.HostName);
                            AddKeyValueRow(table, "User Name", summary.UserName);
                            AddKeyValueRow(table, "OS", summary.OSDescription);
                            AddKeyValueRow(table, "Local IPv4", summary.LocalAddresses.Count == 0 ? "none" : string.Join(" | ", summary.LocalAddresses));
                        });
                    });

                    column.Item().Element(SectionCard).Column(c =>
                    {
                        c.Spacing(4);
                        c.Item().Text("3. Capture Configuration").SemiBold().FontSize(12);
                        c.Item().Table(table =>
                        {
                            table.ColumnsDefinition(cols =>
                            {
                                cols.ConstantColumn(160);
                                cols.RelativeColumn();
                            });

                            AddKeyValueRow(table, "Interface Name", summary.InterfaceName);
                            AddKeyValueRow(table, "Interface Description", summary.InterfaceDescription);
                            AddKeyValueRow(table, "Promiscuous Mode", summary.Promiscuous ? "Enabled" : "Disabled");
                            AddKeyValueRow(table, "Read Timeout (ms)", summary.ReadTimeoutMs.ToString());
                            AddKeyValueRow(table, "BPF Filter", string.IsNullOrWhiteSpace(summary.CaptureFilter) ? "none" : summary.CaptureFilter);
                        });
                    });

                    column.Item().Element(SectionCard).Column(c =>
                    {
                        c.Spacing(6);
                        c.Item().Text("4. Severity Analysis").SemiBold().FontSize(12);

                        c.Item().Table(table =>
                        {
                            table.ColumnsDefinition(cols =>
                            {
                                cols.RelativeColumn(2);
                                cols.RelativeColumn(1);
                                cols.RelativeColumn(1);
                            });

                            table.Header(header =>
                            {
                                HeaderCell(header.Cell(), "Severity");
                                HeaderCell(header.Cell().AlignRight(), "Count");
                                HeaderCell(header.Cell().AlignRight(), "Percent");
                            });

                            var total = Math.Max(1UL, summary.TotalDetections);
                            foreach (var sev in new[] { Core.Enums.SeverityLevel.High, Core.Enums.SeverityLevel.Medium, Core.Enums.SeverityLevel.Low, Core.Enums.SeverityLevel.Info })
                            {
                                summary.SeverityCounts.TryGetValue(sev, out var count);
                                var pct = (count * 100.0) / total;

                                BodyCell(table.Cell(), sev.ToString());
                                BodyCell(table.Cell().AlignRight(), count.ToString("N0"));
                                BodyCell(table.Cell().AlignRight(), $"{pct:0.0}%");
                            }
                        });
                    });

                    column.Item().Element(SectionCard).Column(c =>
                    {
                        c.Spacing(6);
                        c.Item().Text("5. Top Threats").SemiBold().FontSize(12);

                        var topThreats = summary.ThreatCounts.OrderByDescending(x => x.Value).Take(15).ToList();
                        if (topThreats.Count == 0)
                        {
                            c.Item().Text("No detections recorded.");
                        }
                        else
                        {
                            c.Item().Table(table =>
                            {
                                table.ColumnsDefinition(cols =>
                                {
                                    cols.RelativeColumn(5);
                                    cols.RelativeColumn(1);
                                });

                                table.Header(header =>
                                {
                                    HeaderCell(header.Cell(), "Threat Signature");
                                    HeaderCell(header.Cell().AlignRight(), "Count");
                                });

                                foreach (var threat in topThreats)
                                {
                                    BodyCell(table.Cell(), threat.Key);
                                    BodyCell(table.Cell().AlignRight(), threat.Value.ToString("N0"));
                                }
                            });
                        }
                    });
                });

                page.Footer().AlignRight().Text(x =>
                {
                    x.Span("PacketHorn");
                    x.Span(" | ");
                    x.Span(DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss UTC"));
                    x.Span(" | Page ");
                    x.CurrentPageNumber();
                });
            });
        }).GeneratePdf(filePath);

        return filePath;
    }

    private static Action<IContainer> BuildHeader(ReportSummary summary)
    {
        return container =>
        {
            container.Element(SectionCard).Row(row =>
            {
                row.RelativeItem().Column(c =>
                {
                    c.Item().Text("PacketHorn Detection Report").FontSize(18).SemiBold().FontColor(Colors.Blue.Darken2);
                    c.Item().Text("Formal Session Analysis").FontColor(Colors.Grey.Darken1);
                });

                row.RelativeItem().AlignRight().Column(c =>
                {
                    c.Item().Text($"Interface: {summary.InterfaceName}").SemiBold();
                    c.Item().Text($"Generated: {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss UTC}");
                });
            });
        };
    }

    private static IContainer SectionCard(IContainer container)
    {
        return container
            .Border(1)
            .BorderColor(Colors.Grey.Lighten2)
            .Background(Colors.Grey.Lighten4)
            .Padding(8);
    }

    private static void HeaderCell(IContainer container, string text)
    {
        container
            .BorderBottom(1)
            .BorderColor(Colors.Grey.Lighten1)
            .PaddingVertical(3)
            .Text(text)
            .SemiBold();
    }

    private static void BodyCell(IContainer container, string text)
    {
        container
            .BorderBottom(1)
            .BorderColor(Colors.Grey.Lighten3)
            .PaddingVertical(2)
            .Text(string.IsNullOrWhiteSpace(text) ? "-" : text);
    }

    private static void AddKeyValueRow(TableDescriptor table, string key1, string value1, string key2, string value2)
    {
        BodyCell(table.Cell(), key1);
        BodyCell(table.Cell(), value1);
        BodyCell(table.Cell(), key2);
        BodyCell(table.Cell(), value2);
    }

    private static void AddKeyValueRow(TableDescriptor table, string key, string value)
    {
        BodyCell(table.Cell(), key);
        BodyCell(table.Cell(), value);
    }
}
