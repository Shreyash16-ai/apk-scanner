package com.portfolio.apkscanner.report;

import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.portfolio.apkscanner.core.ScanEngine.ScanResult;
import com.portfolio.apkscanner.model.Finding;
import com.portfolio.apkscanner.model.Severity;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * Produces both report formats from the same ScanResult, so there is exactly
 * one source of truth for "what a scan found" and the two renderers can
 * never disagree with each other.
 */
public class ReportWriter {

    private static final List<Severity> SEVERITY_ORDER =
            List.of(Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO);

    public void writeJson(ScanResult result, Path outPath) throws IOException {
        JsonObject root = new JsonObject();
        root.addProperty("scanTimestamp", Instant.now().toString());
        root.addProperty("filesScanned", result.filesScanned());
        root.addProperty("manifestFound", result.manifestFound());
        root.addProperty("parseFailureCount", result.parseFailures().size());

        JsonArray findingsArr = new JsonArray();
        List<Finding> sorted = sortedBySeverity(result.findings());
        for (Finding f : sorted) {
            JsonObject fo = new JsonObject();
            fo.addProperty("ruleId", f.getRuleId());
            fo.addProperty("title", f.getTitle());
            fo.addProperty("severity", f.getSeverity().name());
            fo.addProperty("cwe", f.getCwe());
            fo.addProperty("file", f.getFilePath());
            fo.addProperty("line", f.getLine());
            fo.addProperty("snippet", f.getSnippet());
            fo.addProperty("explanation", f.getExplanation());
            fo.addProperty("recommendation", f.getRecommendation());
            findingsArr.add(fo);
        }
        root.add("findings", findingsArr);

        JsonObject summary = new JsonObject();
        for (var e : countBySeverity(result.findings()).entrySet()) {
            summary.addProperty(e.getKey().name(), e.getValue());
        }
        root.add("severityCounts", summary);

        if (!result.parseFailures().isEmpty()) {
            JsonArray failures = new JsonArray();
            result.parseFailures().forEach(failures::add);
            root.add("parseFailures", failures);
        }

        Files.writeString(outPath, new GsonBuilder().setPrettyPrinting().create().toJson(root));
    }

    public void writeText(ScanResult result, Path outPath) throws IOException {
        StringBuilder sb = new StringBuilder();
        sb.append("=".repeat(70)).append("\n");
        sb.append("APK STATIC ANALYSIS REPORT\n");
        sb.append("=".repeat(70)).append("\n");
        sb.append("Generated: ").append(Instant.now()).append("\n");
        sb.append("Files scanned: ").append(result.filesScanned()).append("\n");
        sb.append("Manifest analyzed: ").append(result.manifestFound() ? "yes" : "no").append("\n");
        if (!result.parseFailures().isEmpty()) {
            sb.append("Parse failures: ").append(result.parseFailures().size())
                    .append(" (see end of report)\n");
        }
        sb.append("\n");

        Map<Severity, Long> counts = countBySeverity(result.findings());
        sb.append("SUMMARY\n").append("-".repeat(70)).append("\n");
        for (Severity s : SEVERITY_ORDER) {
            sb.append(String.format("  %-10s %d%n", s, counts.getOrDefault(s, 0L)));
        }
        sb.append("  TOTAL      ").append(result.findings().size()).append("\n\n");

        List<Finding> sorted = sortedBySeverity(result.findings());
        sb.append("FINDINGS\n").append("=".repeat(70)).append("\n");
        int i = 1;
        for (Finding f : sorted) {
            sb.append("\n[").append(i++).append("] ").append(f.getSeverity())
                    .append(" - ").append(f.getTitle())
                    .append(" (").append(f.getRuleId()).append(", ").append(f.getCwe()).append(")\n");
            sb.append("    File: ").append(f.getFilePath()).append(":").append(f.getLine()).append("\n");
            sb.append("    Code: ").append(f.getSnippet()).append("\n");
            sb.append("    Why it matters: ").append(wrap(f.getExplanation(), 4)).append("\n");
            sb.append("    Fix: ").append(wrap(f.getRecommendation(), 4)).append("\n");
        }

        if (!result.parseFailures().isEmpty()) {
            sb.append("\n").append("-".repeat(70)).append("\n");
            sb.append("FILES THAT FAILED TO PARSE (not scanned)\n");
            result.parseFailures().forEach(p -> sb.append("  - ").append(p).append("\n"));
        }

        Files.writeString(outPath, sb.toString());
    }

    private List<Finding> sortedBySeverity(List<Finding> findings) {
        return findings.stream()
                .sorted(Comparator.comparingInt(f -> SEVERITY_ORDER.indexOf(f.getSeverity())))
                .toList();
    }

    private Map<Severity, Long> countBySeverity(List<Finding> findings) {
        Map<Severity, Long> counts = new TreeMap<>(Comparator.comparingInt(SEVERITY_ORDER::indexOf));
        for (Finding f : findings) {
            counts.merge(f.getSeverity(), 1L, Long::sum);
        }
        return counts;
    }

    /** Minimal indentation-preserving wrap so long explanations don't produce one giant line. */
    private String wrap(String text, int indent) {
        return text; // kept simple on purpose — terminals/editors soft-wrap fine; avoid over-engineering formatting
    }
}
