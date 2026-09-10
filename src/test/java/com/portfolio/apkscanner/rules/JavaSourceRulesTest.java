package com.portfolio.apkscanner.rules;

import com.github.javaparser.JavaParser;
import com.github.javaparser.ParseResult;
import com.github.javaparser.ast.CompilationUnit;
import com.portfolio.apkscanner.model.Finding;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Validates each rule against the two sample files: VulnerableActivity.java
 * (should trip every rule at least once) and CleanActivity.java (should trip
 * none — this is the false-positive check, which matters as much as recall
 * for a portfolio piece: a scanner that flags everything is not credible).
 */
class JavaSourceRulesTest {

    private CompilationUnit vulnerableCu;
    private CompilationUnit cleanCu;
    private final JavaParser parser = new JavaParser();

    @BeforeEach
    void setUp() throws IOException {
        vulnerableCu = parse("vulnerable-samples/VulnerableActivity.java");
        cleanCu = parse("vulnerable-samples/CleanActivity.java");
    }

    private CompilationUnit parse(String resourcePath) throws IOException {
        Path path = Path.of("src/test/resources").resolve(resourcePath);
        String source = Files.readString(path);
        ParseResult<CompilationUnit> result = parser.parse(source);
        assertTrue(result.getResult().isPresent(),
                "Sample file failed to parse: " + resourcePath + " -> " + result.getProblems());
        return result.getResult().get();
    }

    @Test
    void hardcodedSecretRule_detectsKnownFormatAndEntropyHeuristic() {
        HardcodedSecretRule rule = new HardcodedSecretRule();
        List<Finding> findings = rule.apply(vulnerableCu, Path.of("VulnerableActivity.java"));

        assertTrue(findings.size() >= 2,
                "Expected at least 2 findings (known-format key + entropy heuristic), got: " + findings.size());
        assertTrue(findings.stream().anyMatch(f -> f.getTitle().contains("Google API Key")));
        assertTrue(findings.stream().anyMatch(f -> f.getTitle().contains("heuristic")));

        List<Finding> cleanFindings = rule.apply(cleanCu, Path.of("CleanActivity.java"));
        assertTrue(cleanFindings.isEmpty(), "Clean sample should not trip HardcodedSecretRule: " + cleanFindings);
    }

    @Test
    void weakCryptoRule_detectsEcbMd5AndHardcodedIv() {
        WeakCryptoRule rule = new WeakCryptoRule();
        List<Finding> findings = rule.apply(vulnerableCu, Path.of("VulnerableActivity.java"));

        Set<String> titles = findings.stream().map(Finding::getTitle).collect(Collectors.toSet());
        assertTrue(titles.stream().anyMatch(t -> t.contains("ECB")), "Should flag ECB mode: " + titles);
        assertTrue(titles.stream().anyMatch(t -> t.contains("MD5")), "Should flag MD5: " + titles);
        assertTrue(titles.stream().anyMatch(t -> t.contains("Hardcoded IV")), "Should flag hardcoded IV: " + titles);

        List<Finding> cleanFindings = rule.apply(cleanCu, Path.of("CleanActivity.java"));
        assertTrue(cleanFindings.isEmpty(),
                "Clean sample (GCM + SHA-256 + random IV) should not trip WeakCryptoRule: " + cleanFindings);
    }

    @Test
    void insecureStorageRule_detectsWorldReadablePrefsAndExternalStorage() {
        InsecureStorageRule rule = new InsecureStorageRule();
        List<Finding> findings = rule.apply(vulnerableCu, Path.of("VulnerableActivity.java"));

        assertTrue(findings.stream().anyMatch(f -> f.getTitle().contains("World-Readable")));
        assertTrue(findings.stream().anyMatch(f -> f.getTitle().contains("External Storage")));

        List<Finding> cleanFindings = rule.apply(cleanCu, Path.of("CleanActivity.java"));
        assertTrue(cleanFindings.isEmpty(),
                "Clean sample (MODE_PRIVATE, no external storage) should not trip InsecureStorageRule: " + cleanFindings);
    }

    @Test
    void webViewMisconfigRule_detectsJsBridgeAndMixedContent() {
        WebViewMisconfigRule rule = new WebViewMisconfigRule();
        List<Finding> findings = rule.apply(vulnerableCu, Path.of("VulnerableActivity.java"));

        assertTrue(findings.stream().anyMatch(f -> f.getTitle().contains("JavaScript Bridge")));
        assertTrue(findings.stream().anyMatch(f -> f.getTitle().contains("Mixed Content")));

        List<Finding> cleanFindings = rule.apply(cleanCu, Path.of("CleanActivity.java"));
        assertTrue(cleanFindings.isEmpty(), "Clean sample has no WebView usage at all: " + cleanFindings);
    }
}
