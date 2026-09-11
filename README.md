# apk-scanner

A Java/[JavaParser](https://javaparser.org/)-based static analysis tool for finding common Android security vulnerabilities in **decompiled APK source code**. Built as a portfolio project to demonstrate AST-based (rather than regex-based) static analysis.

## What it detects

| Vulnerability class | Rule | CWE | Severity |
|---|---|---|---|
| Hardcoded API keys/secrets (known formats + entropy heuristic) | `HardcodedSecretRule` | CWE-798 | CRITICAL/HIGH/MEDIUM |
| Weak cryptography (ECB mode, MD5/SHA-1, hardcoded IVs, DES/RC4) | `WeakCryptoRule` | CWE-327/329 | HIGH/MEDIUM |
| Insecure local storage (world-readable SharedPreferences, external storage writes) | `InsecureStorageRule` | CWE-732/922 | CRITICAL/MEDIUM |
| WebView misconfiguration (exposed JS bridges, mixed content) | `WebViewMisconfigRule` | CWE-749/319 | HIGH/MEDIUM |
| Exported Activities/Services/Receivers/Providers without permission checks | `ManifestScanner` | CWE-926 | HIGH/CRITICAL |
| Cleartext traffic permitted app-wide | `ManifestScanner` | CWE-319 | HIGH |

Each finding includes: file + line number, a code snippet, **why it's a vulnerability**, and **how to fix it** — not just a flag.

## Why AST-based instead of regex

A regex/text scanner has to *guess* relationships by proximity — it breaks on trivial reformatting (`String key = "a" + "b";`, multi-line declarations, unusual whitespace). This tool parses each `.java` file into a real Abstract Syntax Tree via JavaParser and walks it with visitors (e.g. `VoidVisitorAdapter<VariableDeclarator>`), so detection is based on actual code *structure* — what's assigned to what, which method is being called with which arguments — not text patterns. The one exception is `AndroidManifest.xml`, which is genuinely XML rather than Java, so it's parsed separately with `org.w3c.dom` rather than forced through the same abstraction.

**Explicit scope limit:** rules here are intra-file/intra-method syntax analysis, not full data-flow/taint tracking. For example, `InsecureStorageRule` flags a call to `Environment.getExternalStorageDirectory()` regardless of what's later written there — it doesn't trace whether sensitive data actually reaches that path. This is a deliberate boundary, not an oversight: full taint analysis across files/methods is what turns a rule-based scanner into a much larger undertaking (see "Comparison to MobSF" below).

## How it works — pipeline

```
APK file
  → jadx (decompiler, not included in this repo)
  → decompiled Java source + AndroidManifest.xml
  → ScanEngine walks the source tree, parses each .java file with JavaParser
  → each of 4 rules visits the AST, ManifestScanner parses the XML separately
  → findings merged, sorted by severity
  → ReportWriter emits report.json and report.txt
```

## Usage

**Requirements:** JDK 17+, Maven, and [jadx](https://github.com/skylot/jadx) (for decompiling an APK first — not bundled here).

```bash
# 1. Build
mvn package -DskipTests

# 2. Decompile an APK you have the right to test (see note below)
jadx -d decompiled-output path/to/app.apk

# 3. Scan it
java -jar target/apk-scanner.jar decompiled-output

# Reports land in ./scan-report/report.json and ./scan-report/report.txt
```

You can also point it directly at any folder of `.java` files + an `AndroidManifest.xml` — it doesn't strictly require jadx, that's just the typical source.

> **Only scan APKs you own or have explicit permission to test.** This project was validated against [InsecureBankv2](https://github.com/dineshshetty/Android-InsecureBankv2), an intentionally vulnerable app built specifically for security training.

## Example output

Real results from scanning the decompiled [InsecureBankv2](https://github.com/dineshshetty/Android-InsecureBankv2) APK (2,992 files scanned, including bundled third-party libraries — more on that below):

```
SUMMARY
  CRITICAL   1
  HIGH       8
  MEDIUM     17
  TOTAL      26

[1] CRITICAL - Exported Provider Without Permission Check (EXPORTED_COMPONENT_NO_PERMISSION, CWE-926)
    File: AndroidManifest.xml
    Code: <provider android:name="com.android.insecurebankv2.TrackUserContentProvider" android:exported="true" ...>
    Why it matters: This provider is reachable by any other application on the
    device via an explicit Intent naming its component, with no
    android:permission guard.
    Fix: Set android:exported="false", or require a signature-level custom
    permission if external callers are genuinely needed.

[2] HIGH - Hardcoded IV (WEAK_CRYPTO, CWE-329)
    File: sources/com/android/insecurebankv2/CryptoClass.java:26
    Code: new IvParameterSpec(ivBytes)
    Why it matters: A static IV means encrypting the same plaintext with the
    same key always produces the same ciphertext, defeating the purpose of
    the IV and enabling pattern analysis against CBC mode.
    Fix: Generate the IV randomly per encryption with SecureRandom.

[3] HIGH - Exported Activity Without Permission Check (EXPORTED_COMPONENT_NO_PERMISSION, CWE-926)
    File: AndroidManifest.xml
    Code: <activity android:name="com.android.insecurebankv2.DoTransfer" android:exported="true" ...>
    (Same pattern also found on PostLogin, ChangePassword, and ViewStatement.)

[4] MEDIUM - Suspected hardcoded secret (name + entropy heuristic) (HARDCODED_SECRET, CWE-798)
    File: sources/com/android/insecurebankv2/ChangePassword.java:45
    Code: PASSWORD_PATTERN = "((?=..." (entropy=4.29 bits/char)
    Why it matters: Variable name suggests a credential, and the string's
    randomness is inconsistent with a normal UI string.
```

Full report: [`docs/sample-findings.txt`](docs/sample-findings.txt).

**An honest observation from this scan:** several MEDIUM findings (weak MD5/SHA-1 hashing) appear under `com/google/android/gms/...` — that's Google Play Services, bundled into the APK, not code InsecureBankv2's authors wrote. Scanning decompiled output means scanning *everything* linked into the APK, not just the app's own logic. A real triage pass would deprioritize findings in known third-party libraries; this scanner currently reports all of them and leaves that filtering to the analyst — a documented limitation rather than a hidden one.

## Comparison to MobSF

[MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) is a full mobile security testing platform: static + dynamic analysis, a web UI, malware/API-abuse detection, and broader coverage across manifest, code, and binary-level checks, built on a larger and more mature rule set accumulated over years.

This project is intentionally narrower: a focused, explainable, rule-based **static** scanner covering six specific vulnerability classes end-to-end, with every rule's security reasoning documented inline in the source. The goal wasn't to replace MobSF's breadth, but to demonstrate — end-to-end, in code I wrote and can defend line by line — how AST-based static analysis actually works, including being explicit about where its limits are (no data-flow tracking, no dynamic analysis, no binary-level inspection).

## Project structure

```
src/main/java/com/portfolio/apkscanner/
  core/       ScanEngine (orchestration), Main (CLI)
  rules/      JavaSourceRule interface + the 4 AST-based detectors
  manifest/   ManifestScanner (XML-based, separate from JavaSourceRule)
  model/      Finding, Severity
  report/     ReportWriter (JSON + text output)
src/test/     JUnit tests + the vulnerable/clean sample corpus
```

