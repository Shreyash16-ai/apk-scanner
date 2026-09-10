package com.portfolio.apkscanner.rules;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.expr.BooleanLiteralExpr;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.visitor.VoidVisitorAdapter;
import com.portfolio.apkscanner.model.Finding;
import com.portfolio.apkscanner.model.Severity;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Detects WebView misconfigurations:
 *   1. addJavascriptInterface(...) combined with setJavaScriptEnabled(true)
 *      in the same class — a JS bridge exposed to page content.
 *   2. setMixedContentMode(MIXED_CONTENT_ALWAYS_ALLOW).
 *
 * SECURITY REASONING (for interview defense):
 *
 * - JS BRIDGE (addJavascriptInterface): this exposes a Java object's public
 *   methods to JavaScript running in the WebView. If that WebView ever loads
 *   ANY attacker-influenceable content — a page over HTTP, a URL built from
 *   an Intent extra, a page with an XSS flaw — the attacker's JS can call
 *   into your Java object directly. On API <17 this was RCE-level (arbitrary
 *   method invocation via reflection, CVE-2012-6636 era); on API 17+ Android
 *   requires @JavascriptInterface annotations to limit exposure, but the
 *   fundamental exposure of app-internal functionality to untrusted web
 *   content remains the risk. CWE-749 (Exposed Dangerous Method or Function).
 *   This scanner flags the addJavascriptInterface call and separately checks
 *   whether setJavaScriptEnabled(true) appears in the same class, since the
 *   bridge is inert without JS execution enabled.
 *
 * - MIXED_CONTENT_ALWAYS_ALLOW: permits a page loaded over HTTPS to load
 *   sub-resources (scripts, iframes) over plain HTTP. An on-path attacker
 *   can inject/modify that HTTP sub-resource — most dangerously an HTTP
 *   <script> tag — and that injected script runs with the security
 *   privileges of the HTTPS parent page, fully undermining the confidentiality
 *   and integrity guarantees TLS was providing. CWE-319.
 *
 * DETECTION STRATEGY: per-class (per MethodDeclaration container, i.e. the
 * enclosing ClassOrInterfaceDeclaration) scan for the relevant method-call
 * names. Like the crypto rule, this is intra-file/intra-class syntax
 * matching, not true data-flow linking a specific WebView instance to a
 * specific bridge object — documented as the scanner's scope boundary.
 */
public class WebViewMisconfigRule implements JavaSourceRule {

    @Override
    public String getId() { return "WEBVIEW_MISCONFIG"; }

    @Override
    public String getName() { return "WebView Misconfiguration"; }

    @Override
    public List<Finding> apply(CompilationUnit cu, Path filePath) {
        List<Finding> findings = new ArrayList<>();

        // Track whether setJavaScriptEnabled(true) appears anywhere in the file
        // (simple file-scoped heuristic — see class javadoc on scope limits).
        final boolean[] jsEnabled = {false};
        cu.accept(new VoidVisitorAdapter<Void>() {
            @Override
            public void visit(MethodCallExpr call, Void arg) {
                super.visit(call, arg);
                if (call.getNameAsString().equals("setJavaScriptEnabled") && !call.getArguments().isEmpty()) {
                    Expression a0 = call.getArgument(0);
                    if (a0 instanceof BooleanLiteralExpr && ((BooleanLiteralExpr) a0).getValue()) {
                        jsEnabled[0] = true;
                    }
                }
            }
        }, null);

        cu.accept(new VoidVisitorAdapter<Void>() {
            @Override
            public void visit(MethodCallExpr call, Void arg) {
                super.visit(call, arg);
                String methodName = call.getNameAsString();
                int line = call.getRange().map(r -> r.begin.line).orElse(-1);

                if (methodName.equals("addJavascriptInterface")) {
                    Severity sev = jsEnabled[0] ? Severity.HIGH : Severity.MEDIUM;
                    findings.add(new Finding(
                            getId(), "JavaScript Bridge Exposed to WebView", sev, "CWE-749",
                            filePath.toString(), line,
                            truncate(call.toString()),
                            "addJavascriptInterface exposes this Java object's annotated methods to " +
                                    "JavaScript executing inside the WebView" +
                                    (jsEnabled[0] ? " (setJavaScriptEnabled(true) confirmed in this file)." :
                                            " (setJavaScriptEnabled(true) was not found in this file — " +
                                                    "verify it's not enabled elsewhere, e.g. a shared config method).") +
                                    " If the WebView ever loads untrusted or attacker-influenceable content " +
                                    "(HTTP pages, externally-supplied URLs, content with an XSS flaw), that " +
                                    "content can invoke this bridge's methods directly.",
                            "Only annotate methods that are safe to expose to arbitrary web content with " +
                                    "@JavascriptInterface. Load only trusted, HTTPS content in this WebView, " +
                                    "and consider removing the bridge if it's not essential."
                    ));
                } else if (methodName.equals("setMixedContentMode") && !call.getArguments().isEmpty()) {
                    String argStr = call.getArgument(0).toString();
                    if (argStr.contains("MIXED_CONTENT_ALWAYS_ALLOW")) {
                        findings.add(new Finding(
                                getId(), "Mixed Content Always Allowed", Severity.HIGH, "CWE-319",
                                filePath.toString(), line,
                                truncate(call.toString()),
                                "MIXED_CONTENT_ALWAYS_ALLOW lets an HTTPS page load HTTP sub-resources. " +
                                        "An attacker on the network path can tamper with that HTTP resource " +
                                        "(e.g. inject a malicious <script>), and it will execute with the " +
                                        "privileges of the HTTPS page — defeating the point of using HTTPS.",
                                "Use MIXED_CONTENT_NEVER_ALLOW (default on API 21+), or " +
                                        "MIXED_CONTENT_COMPATIBILITY_MODE only if you have a specific, " +
                                        "reviewed reason to."
                        ));
                    }
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
