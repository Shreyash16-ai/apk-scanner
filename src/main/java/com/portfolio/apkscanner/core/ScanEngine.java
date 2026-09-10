package com.portfolio.apkscanner.core;

import com.github.javaparser.JavaParser;
import com.github.javaparser.ParseResult;
import com.github.javaparser.ParserConfiguration;
import com.github.javaparser.ast.CompilationUnit;
import com.portfolio.apkscanner.manifest.ManifestScanner;
import com.portfolio.apkscanner.model.Finding;
import com.portfolio.apkscanner.rules.JavaSourceRule;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

/**
 * Orchestrates a scan: walk the decompiled source tree, parse each .java
 * file, run every registered rule against it, and separately hand off
 * AndroidManifest.xml (if present) to the ManifestScanner.
 *
 * Parse failures are collected rather than thrown — decompiled output from
 * jadx is not always valid Java (synthetic bridge methods, illegal
 * identifiers, etc.), and a scanner that dies on the first bad file is
 * useless against a whole APK. We report what failed alongside what
 * succeeded, which is itself an honest, reportable property of a real tool.
 */
public class ScanEngine {

    private final List<JavaSourceRule> rules;
    private final ManifestScanner manifestScanner = new ManifestScanner();
    private final JavaParser javaParser;

    public ScanEngine(List<JavaSourceRule> rules) {
        this.rules = rules;
        // JavaParser needs to know the language level to parse modern syntax
        // (var, switch expressions, records) that decompilers may emit.
        ParserConfiguration config = new ParserConfiguration();
        config.setLanguageLevel(ParserConfiguration.LanguageLevel.JAVA_17);
        this.javaParser = new JavaParser(config);
    }

    public ScanResult scan(Path root) throws IOException {
        List<Finding> findings = new ArrayList<>();
        List<String> parseFailures = new ArrayList<>();
        int filesScanned = 0;

        try (Stream<Path> paths = Files.walk(root)) {
            List<Path> javaFiles = paths
                    .filter(p -> p.toString().endsWith(".java"))
                    .toList();

            for (Path file : javaFiles) {
                try {
                    String source = Files.readString(file);
                    ParseResult<CompilationUnit> result = javaParser.parse(source);
                    if (result.getResult().isEmpty()) {
                        parseFailures.add(file.toString());
                        continue;
                    }
                    CompilationUnit cu = result.getResult().get();
                    filesScanned++;
                    for (JavaSourceRule rule : rules) {
                        findings.addAll(rule.apply(cu, root.relativize(file)));
                    }
                } catch (Exception e) {
                    // One bad file must not abort the whole scan.
                    parseFailures.add(file.toString() + " (" + e.getMessage() + ")");
                }
            }
        }

        // Manifest: look for it at the root or one level down (common jadx
        // output layout is <output>/resources/AndroidManifest.xml or
        // <output>/AndroidManifest.xml depending on tool/version).
        Path manifest = findManifest(root);
        if (manifest != null) {
            try {
                findings.addAll(manifestScanner.scan(manifest));
            } catch (Exception e) {
                parseFailures.add(manifest + " (manifest parse error: " + e.getMessage() + ")");
            }
        }

        return new ScanResult(findings, filesScanned, parseFailures, manifest != null);
    }

    private Path findManifest(Path root) throws IOException {
        try (Stream<Path> paths = Files.walk(root, 3)) {
            return paths.filter(p -> p.getFileName().toString().equals("AndroidManifest.xml"))
                    .findFirst()
                    .orElse(null);
        }
    }

    /** Result of a full scan run, including bookkeeping useful in the report header. */
    public record ScanResult(List<Finding> findings, int filesScanned,
                              List<String> parseFailures, boolean manifestFound) {}
}
