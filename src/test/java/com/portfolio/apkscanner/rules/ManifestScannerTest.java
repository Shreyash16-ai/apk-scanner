package com.portfolio.apkscanner.rules;

import com.portfolio.apkscanner.manifest.ManifestScanner;
import com.portfolio.apkscanner.model.Finding;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class ManifestScannerTest {

    @Test
    void flagsExportedComponentsWithoutPermission_andSkipsGuardedOrLauncherOrNonExported() throws Exception {
        ManifestScanner scanner = new ManifestScanner();
        Path manifest = Path.of("src/test/resources/vulnerable-samples/AndroidManifest.xml");

        List<Finding> findings = scanner.scan(manifest);

        // Should flag: ChangePasswordActivity (explicit export), SmsReceiver (implicit
        // via intent-filter), UserDataProvider (explicit export, provider => CRITICAL)
        assertTrue(findings.stream().anyMatch(f -> f.getSnippet().contains("ChangePasswordActivity")));
        assertTrue(findings.stream().anyMatch(f -> f.getSnippet().contains("SmsReceiver")));
        assertTrue(findings.stream().anyMatch(f -> f.getSnippet().contains("UserDataProvider")));

        // Should NOT flag: MainActivity (launcher), SecureSyncService (permission-guarded),
        // InternalSettingsActivity (exported=false)
        assertFalse(findings.stream().anyMatch(f -> f.getSnippet().contains("MainActivity")));
        assertFalse(findings.stream().anyMatch(f -> f.getSnippet().contains("SecureSyncService")));
        assertFalse(findings.stream().anyMatch(f -> f.getSnippet().contains("InternalSettingsActivity")));

        // Cleartext traffic check
        assertTrue(findings.stream().anyMatch(f -> f.getRuleId().equals("CLEARTEXT_TRAFFIC")));
    }
}
