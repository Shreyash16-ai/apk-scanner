package com.portfolio.apkscanner.rules;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.VariableDeclarator;
import com.github.javaparser.ast.expr.AssignExpr;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.StringLiteralExpr;
import com.github.javaparser.ast.visitor.VoidVisitorAdapter;
import com.portfolio.apkscanner.model.Finding;
import com.portfolio.apkscanner.model.Severity;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Detects hardcoded secrets (API keys, tokens, credentials) embedded as
 * String literals in Java source.
 *
 * SECURITY REASONING (for interview defense):
 * Anything compiled into an APK is trivially recoverable — jadx/apktool
 * decompilation is exactly the attack this rule assumes. A secret baked into
 * source is:
 *   1. Extractable by ANY user of the app, not just a sophisticated attacker
 *      (this is literally what our own pipeline does to find it).
 *   2. Unrotatable without shipping a new app version and hoping every user
 *      updates — unlike a server-side secret you can revoke instantly.
 *   3. Often over-privileged, because "just embed the key" skips whatever
 *      scoping/short-lived-token design a proper backend-mediated auth flow
 *      would force the developer to think about.
 * CWE-798 (Use of Hard-coded Credentials) is the standard reference here.
 *
 * DETECTION STRATEGY:
 * We combine two independent signals rather than relying on either alone:
 *   (a) KNOWN FORMATS: regex signatures for well-known key shapes (AWS,
 *       Google API keys, Stripe, Slack, generic JWT/bearer patterns). High
 *       precision, but only catches key issuers we've enumerated.
 *   (b) NAME + ENTROPY HEURISTIC: a String literal assigned to a
 *       suspiciously-named variable (key/secret/token/password/apiKey/...)
 *       AND with high Shannon entropy (i.e., it "looks random", not like an
 *       English word or a UI label). This catches custom/internal secret
 *       formats the regex list doesn't know about, at the cost of some
 *       false positives on things like UUIDs used as non-secret IDs — which
 *       is why this path is flagged MEDIUM rather than HIGH/CRITICAL.
 *
 * This mirrors how real secret scanners (gitleaks, truffleHog) work: known
 * signatures for precision, entropy for recall on the long tail.
 */
public class HardcodedSecretRule implements JavaSourceRule {

    @Override
    public String getId() { return "HARDCODED_SECRET"; }

    @Override
    public String getName() { return "Hardcoded API Key / Secret"; }

    // --- (a) Known secret format signatures -------------------------------
    private static final List<KnownFormat> KNOWN_FORMATS = List.of(
            new KnownFormat("AWS Access Key ID", Pattern.compile("AKIA[0-9A-Z]{16}"), Severity.CRITICAL),
            new KnownFormat("Google API Key", Pattern.compile("AIza[0-9A-Za-z\\-_]{35}"), Severity.CRITICAL),
            new KnownFormat("Stripe Secret Key", Pattern.compile("sk_live_[0-9a-zA-Z]{16,}"), Severity.CRITICAL),
            new KnownFormat("Slack Token", Pattern.compile("xox[baprs]-[0-9A-Za-z-]{10,}"), Severity.CRITICAL),
            new KnownFormat("Generic JWT", Pattern.compile("eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+"), Severity.HIGH)
    );

    // --- (b) Name heuristic for the entropy path ---------------------------
    private static final Pattern SUSPICIOUS_NAME = Pattern.compile(
            "(?i)(secret|apikey|api_key|password|passwd|token|access[_]?key|private[_]?key|auth[_]?key|credential)"
    );

    private static final double ENTROPY_THRESHOLD = 3.5; // bits/char; tuned to skip prose/UI strings
    private static final int MIN_LENGTH_FOR_ENTROPY_CHECK = 12; // skip short strings, too noisy

    @Override
    public List<Finding> apply(CompilationUnit cu, Path filePath) {
        List<Finding> findings = new ArrayList<>();

        // Case 1: String literal in a variable DECLARATION with initializer
        // e.g. String apiKey = "AIzaSy...";
        cu.accept(new VoidVisitorAdapter<Void>() {
            @Override
            public void visit(VariableDeclarator vd, Void arg) {
                super.visit(vd, arg);
                vd.getInitializer().ifPresent(init -> {
                    if (init instanceof StringLiteralExpr) {
                        checkLiteral(vd.getNameAsString(), (StringLiteralExpr) init, filePath, findings);
                    }
                });
            }
        }, null);

        // Case 2: String literal in a plain ASSIGNMENT (not declaration)
        // e.g. this.secret = "..."; or secret = "..." later in a method.
        cu.accept(new VoidVisitorAdapter<Void>() {
            @Override
            public void visit(AssignExpr ae, Void arg) {
                super.visit(ae, arg);
                Expression rhs = ae.getValue();
                if (rhs instanceof StringLiteralExpr) {
                    checkLiteral(ae.getTarget().toString(), (StringLiteralExpr) rhs, filePath, findings);
                }
            }
        }, null);

        return findings;
    }

    private void checkLiteral(String varName, StringLiteralExpr lit, Path filePath, List<Finding> out) {
        String value = lit.asString();
        int line = lit.getRange().map(r -> r.begin.line).orElse(-1);

        // (a) known formats first — highest confidence, independent of variable name
        for (KnownFormat kf : KNOWN_FORMATS) {
            if (kf.pattern.matcher(value).find()) {
                out.add(new Finding(
                        getId(),
                        "Hardcoded " + kf.label,
                        kf.severity,
                        "CWE-798",
                        filePath.toString(),
                        line,
                        truncate(varName + " = \"" + redact(value) + "\""),
                        "This string matches the known format of a " + kf.label +
                                ". Anyone who decompiles this APK (jadx, apktool, or even 'strings' " +
                                "on the DEX) recovers this credential directly.",
                        "Remove this from source. Fetch the credential at runtime from a backend " +
                                "you control, or use Android Keystore for values that must live on-device."
                ));
                return; // one finding per literal is enough; don't double-report via heuristic below
            }
        }

        // (b) name + entropy heuristic
        if (SUSPICIOUS_NAME.matcher(varName).find()
                && value.length() >= MIN_LENGTH_FOR_ENTROPY_CHECK
                && shannonEntropy(value) >= ENTROPY_THRESHOLD) {
            out.add(new Finding(
                    getId(),
                    "Suspected hardcoded secret (name + entropy heuristic)",
                    Severity.MEDIUM,
                    "CWE-798",
                    filePath.toString(),
                    line,
                    truncate(varName + " = \"" + redact(value) + "\""),
                    "Variable name '" + varName + "' suggests a credential, and the assigned string " +
                            "has high randomness (entropy=" + String.format("%.2f", shannonEntropy(value)) +
                            " bits/char), consistent with a key/token rather than a UI string. " +
                            "Flagged at MEDIUM confidence since this is a heuristic, not a signature match.",
                    "Manually verify whether this is a real secret. If so, move it server-side or into " +
                            "Android Keystore rather than compiling it into the app."
            ));
        }
    }

    /** Redacts the middle of a secret for safe display in reports (don't leak the real value into your own report). */
    private static String redact(String value) {
        if (value.length() <= 8) return "*".repeat(value.length());
        return value.substring(0, 4) + "*".repeat(Math.max(4, value.length() - 8)) + value.substring(value.length() - 4);
    }

    private static String truncate(String s) {
        return s.length() > 120 ? s.substring(0, 117) + "..." : s;
    }

    /** Standard Shannon entropy over the character distribution, in bits/char. */
    static double shannonEntropy(String s) {
        int[] freq = new int[256];
        for (char c : s.toCharArray()) {
            freq[c & 0xFF]++;
        }
        double entropy = 0.0;
        int len = s.length();
        for (int f : freq) {
            if (f == 0) continue;
            double p = (double) f / len;
            entropy -= p * (Math.log(p) / Math.log(2));
        }
        return entropy;
    }

    private static final class KnownFormat {
        final String label;
        final Pattern pattern;
        final Severity severity;
        KnownFormat(String label, Pattern pattern, Severity severity) {
            this.label = label;
            this.pattern = pattern;
            this.severity = severity;
        }
    }
}
