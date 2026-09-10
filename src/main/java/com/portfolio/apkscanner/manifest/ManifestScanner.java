package com.portfolio.apkscanner.manifest;

import com.portfolio.apkscanner.model.Finding;
import com.portfolio.apkscanner.model.Severity;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.File;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Scans AndroidManifest.xml for:
 *   1. Exported Activities/Services/Receivers/Providers with no permission
 *      guard (either no android:permission attribute, and no matching
 *      <intent-filter> that would justify export, e.g. launcher activity).
 *   2. android:usesCleartextTraffic="true" at the <application> level.
 *
 * WHY THIS LIVES SEPARATELY FROM JavaSourceRule:
 * The manifest is XML, decompiled/extracted separately from Java sources by
 * jadx/apktool. Trying to force this through the same "AST visitor" interface
 * as the Java rules would be a false abstraction — the input format, the
 * parsing library (DOM here, JavaParser there), and the traversal model are
 * all different. Two small, honest interfaces beat one leaky "unified" one.
 *
 * SECURITY REASONING (for interview defense):
 * An exported component (android:exported="true", or implicitly exported in
 * older API levels when it declares an <intent-filter>) is reachable by ANY
 * other app installed on the device via an explicit Intent to its component
 * name — not just apps the user trusts. If that component performs a
 * sensitive action (reads local data, makes a network call with stored
 * credentials, launches a WebView with a bridge) without checking a
 * caller-held permission, any malicious app can trigger it. This is the
 * single most common finding in Android CTF-style vulnerable apps
 * (InsecureBankv2 uses this exact pattern in ChangePassword/DoTransfer
 * activities) and is CWE-926 (Improper Export of Android Application
 * Components).
 */
public class ManifestScanner {

    private static final List<String> COMPONENT_TAGS = List.of("activity", "service", "receiver", "provider");

    public List<Finding> scan(Path manifestPath) throws Exception {
        List<Finding> findings = new ArrayList<>();

        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        // Harden the parser against XXE — ironic to introduce a vulnerability
        // while building a vulnerability scanner.
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        dbf.setXIncludeAware(false);
        dbf.setExpandEntityReferences(false);
        DocumentBuilder builder = dbf.newDocumentBuilder();
        Document doc = builder.parse(new File(manifestPath.toString()));
        doc.getDocumentElement().normalize();

        // --- Check 1: exported components without permission ---
        for (String tag : COMPONENT_TAGS) {
            NodeList nodes = doc.getElementsByTagName(tag);
            for (int i = 0; i < nodes.getLength(); i++) {
                Element el = (Element) nodes.item(i);
                findings.addAll(checkComponent(el, tag, manifestPath));
            }
        }

        // --- Check 2: cleartext traffic ---
        NodeList appNodes = doc.getElementsByTagName("application");
        if (appNodes.getLength() > 0) {
            Element application = (Element) appNodes.item(0);
            String cleartext = application.getAttribute("android:usesCleartextTraffic");
            if ("true".equalsIgnoreCase(cleartext)) {
                findings.add(new Finding(
                        "CLEARTEXT_TRAFFIC", "Cleartext Traffic Permitted", Severity.HIGH, "CWE-319",
                        manifestPath.toString(), -1,
                        "<application android:usesCleartextTraffic=\"true\" ...>",
                        "The app explicitly opts into unencrypted HTTP traffic app-wide. Any " +
                                "network request not pinned to HTTPS is readable and tamperable by " +
                                "anyone on the network path (public WiFi, a malicious router, etc.) — " +
                                "a classic man-in-the-middle setup.",
                        "Remove this attribute (default is false since API 28) or scope it via a " +
                                "Network Security Config XML to only the specific legacy domains that " +
                                "truly require it, rather than the whole app."
                ));
            }
            // Absence of the attribute on apps targeting <API 28 is ALSO a risk but requires
            // reading targetSdkVersion from the build tools output, not the manifest alone —
            // documented as a known gap rather than guessed at.
        }

        return findings;
    }

    private List<Finding> checkComponent(Element el, String tag, Path manifestPath) {
        List<Finding> out = new ArrayList<>();
        String name = el.getAttribute("android:name");
        String exportedAttr = el.getAttribute("android:exported");
        String permission = el.getAttribute("android:permission");
        boolean hasIntentFilter = el.getElementsByTagName("intent-filter").getLength() > 0;

        boolean isExplicitlyExported = "true".equalsIgnoreCase(exportedAttr);
        // Pre-API-31 apps: a component with an intent-filter and NO explicit
        // android:exported attribute is implicitly exported by the platform.
        boolean isImplicitlyExported = exportedAttr.isEmpty() && hasIntentFilter;

        if (!(isExplicitlyExported || isImplicitlyExported)) {
            return out; // not exported, nothing to flag
        }
        if (!permission.isEmpty()) {
            return out; // exported but permission-guarded — acceptable pattern
        }

        // The main launcher activity is exported by design and doesn't need
        // a permission check (it's meant to be user-launchable) — exclude it
        // to avoid a guaranteed false positive on every single app.
        if (tag.equals("activity") && isLauncherActivity(el)) {
            return out;
        }

        Severity severity = tag.equals("provider") ? Severity.CRITICAL : Severity.HIGH;
        out.add(new Finding(
                "EXPORTED_COMPONENT_NO_PERMISSION",
                "Exported " + capitalize(tag) + " Without Permission Check",
                severity, "CWE-926",
                manifestPath.toString(), -1,
                "<" + tag + " android:name=\"" + name + "\" " +
                        (isExplicitlyExported ? "android:exported=\"true\"" : "(implicitly exported via intent-filter)") + " ...>",
                "This " + tag + " is reachable by any other application on the device via an " +
                        "explicit Intent naming its component, with no android:permission guard. " +
                        "If it performs a sensitive action (reads stored data, makes authenticated " +
                        "network calls, renders attacker-influenceable content), a malicious co-installed " +
                        "app can trigger it directly, bypassing your app's normal UI/auth flow entirely.",
                "If this component doesn't need to be called from other apps, set " +
                        "android:exported=\"false\" explicitly. If it does need external callers, " +
                        "define a signature-level custom permission and require it via " +
                        "android:permission, and validate any Intent extras defensively regardless."
        ));
        return out;
    }

    private boolean isLauncherActivity(Element activityEl) {
        NodeList filters = activityEl.getElementsByTagName("intent-filter");
        for (int i = 0; i < filters.getLength(); i++) {
            Element filter = (Element) filters.item(i);
            NodeList categories = filter.getElementsByTagName("category");
            for (int j = 0; j < categories.getLength(); j++) {
                Element cat = (Element) categories.item(j);
                if ("android.intent.category.LAUNCHER".equals(cat.getAttribute("android:name"))) {
                    return true;
                }
            }
        }
        return false;
    }

    private String capitalize(String s) {
        return s.substring(0, 1).toUpperCase() + s.substring(1);
    }
}
