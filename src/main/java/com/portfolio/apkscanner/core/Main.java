package com.portfolio.apkscanner.core;

import com.portfolio.apkscanner.report.ReportWriter;
import com.portfolio.apkscanner.rules.HardcodedSecretRule;
import com.portfolio.apkscanner.rules.InsecureStorageRule;
import com.portfolio.apkscanner.rules.JavaSourceRule;
import com.portfolio.apkscanner.rules.WeakCryptoRule;
import com.portfolio.apkscanner.rules.WebViewMisconfigRule;

import java.nio.file.Path;
import java.util.List;

/**
 * Usage: java -jar apk-scanner.jar <path-to-decompiled-source-root> [output-dir]
 *
 * <path-to-decompiled-source-root> is the output of jadx/apktool — a directory
 * containing .java files and (optionally) AndroidManifest.xml.
 */
public class Main {

    public static void main(String[] args) {
        if (args.length < 1) {
            System.err.println("Usage: java -jar apk-scanner.jar <decompiled-source-root> [output-dir]");
            System.exit(1);
        }

        Path root = Path.of(args[0]);
        Path outDir = Path.of(args.length > 1 ? args[1] : "scan-report");

        if (!root.toFile().isDirectory()) {
            System.err.println("Not a directory: " + root);
            System.exit(1);
        }

        List<JavaSourceRule> rules = List.of(
                new HardcodedSecretRule(),
                new WeakCryptoRule(),
                new InsecureStorageRule(),
                new WebViewMisconfigRule()
                // ManifestScanner handles exported-component checks separately (XML, not Java AST)
        );

        try {
            outDir.toFile().mkdirs();
            ScanEngine engine = new ScanEngine(rules);

            System.out.println("Scanning " + root + " ...");
            ScanEngine.ScanResult result = engine.scan(root);

            System.out.println("Files scanned: " + result.filesScanned());
            System.out.println("Findings: " + result.findings().size());
            if (!result.parseFailures().isEmpty()) {
                System.out.println("Files that failed to parse: " + result.parseFailures().size());
            }

            ReportWriter writer = new ReportWriter();
            Path jsonPath = outDir.resolve("report.json");
            Path textPath = outDir.resolve("report.txt");
            writer.writeJson(result, jsonPath);
            writer.writeText(result, textPath);

            System.out.println("Reports written to:");
            System.out.println("  " + jsonPath.toAbsolutePath());
            System.out.println("  " + textPath.toAbsolutePath());

        } catch (Exception e) {
            System.err.println("Scan failed: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }
}
