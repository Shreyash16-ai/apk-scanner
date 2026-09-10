package com.portfolio.apkscanner.rules;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.expr.FieldAccessExpr;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.visitor.VoidVisitorAdapter;
import com.portfolio.apkscanner.model.Finding;
import com.portfolio.apkscanner.model.Severity;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Detects insecure local storage patterns:
 *   1. SharedPreferences opened with MODE_WORLD_READABLE / MODE_WORLD_WRITEABLE
 *      (deprecated since API 17, but still shows up in legacy/vulnerable apps
 *      and is exactly what InsecureBankv2 demonstrates).
 *   2. Writing to external storage (getExternalStorageDirectory /
 *      getExternalFilesDir) without any nearby sign of encryption.
 *
 * SECURITY REASONING (for interview defense):
 *
 * - MODE_WORLD_READABLE/WRITEABLE: makes the resulting file readable (or
 *   writable) by every other application on the device, regardless of
 *   permissions — this was such a common footgun that Android deprecated
 *   the constants entirely and throws a SecurityException on modern API
 *   levels. Any app storing session tokens, PII, or credentials this way
 *   hands them to every other app on the phone. CWE-732 (Incorrect
 *   Permission Assignment for Critical Resource).
 *
 * - External storage (SD card / shared storage): historically had no
 *   per-app access control at all (any app with READ_EXTERNAL_STORAGE could
 *   read any app's external files). Even with post-API 19 sandboxing
 *   (scoped storage in API 29+), writing sensitive data there is risky
 *   because it survives app uninstall, is visible via USB/file managers,
 *   and is backed up more permissively than internal storage. CWE-922
 *   (Insecure Storage of Sensitive Information).
 *
 * DETECTION STRATEGY: pattern-match specific well-known API calls
 * (Context.getSharedPreferences with a MODE_WORLD_* field access argument;
 * Environment.getExternalStorageDirectory / Context.getExternalFilesDir).
 * This is intentionally syntax-level, not data-flow — we are NOT tracing
 * whether the resulting File/Preferences object later receives sensitive
 * data. That would require taint tracking across the method, which is out
 * of scope (see project scope notes). Instead we flag the call site itself
 * and let the analyst judge sensitivity, which is a defensible, explicit
 * limitation rather than a false claim of certainty.
 */
public class InsecureStorageRule implements JavaSourceRule {

    @Override
    public String getId() { return "INSECURE_STORAGE"; }

    @Override
    public String getName() { return "Insecure Local Storage"; }

    @Override
    public List<Finding> apply(CompilationUnit cu, Path filePath) {
        List<Finding> findings = new ArrayList<>();

        cu.accept(new VoidVisitorAdapter<Void>() {
            @Override
            public void visit(MethodCallExpr call, Void arg) {
                super.visit(call, arg);
                String methodName = call.getNameAsString();
                int line = call.getRange().map(r -> r.begin.line).orElse(-1);

                if (methodName.equals("getSharedPreferences")) {
                    for (var argExpr : call.getArguments()) {
                        if (argExpr instanceof FieldAccessExpr) {
                            String field = ((FieldAccessExpr) argExpr).getNameAsString();
                            if (field.equals("MODE_WORLD_READABLE") || field.equals("MODE_WORLD_WRITEABLE")) {
                                findings.add(new Finding(
                                        getId(), "World-Readable/Writable SharedPreferences",
                                        Severity.CRITICAL, "CWE-732",
                                        filePath.toString(), line,
                                        truncate(call.toString()),
                                        "getSharedPreferences(..., " + field + ") makes this preferences " +
                                                "file readable/writable by every other app on the device, " +
                                                "with no permission check. Any data stored here (session " +
                                                "tokens, flags, cached credentials) is exposed device-wide.",
                                        "Use Context.MODE_PRIVATE (the default and only non-deprecated " +
                                                "option). If data must be shared between your own apps, use " +
                                                "a ContentProvider with a signature-level permission instead."
                                ));
                            }
                        }
                    }
                } else if (methodName.equals("getExternalStorageDirectory") || methodName.equals("getExternalFilesDir")) {
                    findings.add(new Finding(
                            getId(), "Write to External Storage", Severity.MEDIUM, "CWE-922",
                            filePath.toString(), line,
                            truncate(call.toString()),
                            "This call obtains a path on external/shared storage. If sensitive data " +
                                    "(credentials, PII, tokens) is subsequently written here, it survives " +
                                    "app uninstall, may be readable by other apps depending on API level " +
                                    "and permissions, and is visible via USB/file manager access. " +
                                    "(Flagged for manual review — this scanner does not trace whether the " +
                                    "resulting path is actually used for sensitive data.)",
                            "Prefer internal storage (Context.getFilesDir()) for anything sensitive, " +
                                    "and use EncryptedFile / Android Keystore-backed encryption if the data " +
                                    "must live outside internal storage."
                    ));
                }
            }
        }, null);

        return findings;
    }

    private static String truncate(String s) {
        s = s.replaceAll("\\s+", " ").trim();
        return s.length() > 140 ? s.substring(0, 137) + "..." : s;
    }
}
