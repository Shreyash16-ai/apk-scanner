package com.portfolio.apkscanner.model;

import java.util.Objects;

/**
 * A single detected issue. Every rule in the scanner produces zero or more
 * of these. Keeping this model rule-agnostic (no rule-specific subclasses)
 * is what lets the report layer stay generic — JSON/text renderers never
 * need to know about individual rule internals.
 */
public final class Finding {
    private final String ruleId;          // e.g. "HARDCODED_SECRET"
    private final String title;           // short human title
    private final Severity severity;
    private final String cwe;             // e.g. "CWE-798" — for interview/report credibility
    private final String filePath;
    private final int line;
    private final String snippet;         // the offending source fragment (trimmed)
    private final String explanation;     // WHY this is a vulnerability
    private final String recommendation;  // HOW to fix it

    public Finding(String ruleId, String title, Severity severity, String cwe,
                    String filePath, int line, String snippet,
                    String explanation, String recommendation) {
        this.ruleId = ruleId;
        this.title = title;
        this.severity = severity;
        this.cwe = cwe;
        this.filePath = filePath;
        this.line = line;
        this.snippet = snippet;
        this.explanation = explanation;
        this.recommendation = recommendation;
    }

    public String getRuleId() { return ruleId; }
    public String getTitle() { return title; }
    public Severity getSeverity() { return severity; }
    public String getCwe() { return cwe; }
    public String getFilePath() { return filePath; }
    public int getLine() { return line; }
    public String getSnippet() { return snippet; }
    public String getExplanation() { return explanation; }
    public String getRecommendation() { return recommendation; }

    @Override
    public String toString() {
        return String.format("[%s] %s:%d - %s (%s)", severity, filePath, line, title, ruleId);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Finding)) return false;
        Finding f = (Finding) o;
        return line == f.line && Objects.equals(ruleId, f.ruleId)
                && Objects.equals(filePath, f.filePath) && Objects.equals(snippet, f.snippet);
    }

    @Override
    public int hashCode() {
        return Objects.hash(ruleId, filePath, line, snippet);
    }
}
