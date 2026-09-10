package com.example.vulnerableapp;

import android.app.Activity;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.Bundle;
import javax.crypto.Cipher;
import java.security.MessageDigest;
import java.security.SecureRandom;

/**
 * Deliberately "clean" sample using safer equivalents of every pattern in
 * VulnerableActivity, so the test suite proves the scanner doesn't just
 * fire on the presence of Cipher/MessageDigest/SharedPreferences generally.
 */
public class CleanActivity extends Activity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // MODE_PRIVATE, not MODE_WORLD_READABLE — should NOT be flagged
        SharedPreferences prefs = getSharedPreferences("user_session", Context.MODE_PRIVATE);

        // Cache key, not a secret variable name / not high-entropy security use
        String cacheDirName = "cache_v2";

        try {
            // GCM, not ECB — should NOT be flagged
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

            // Randomly generated IV, not a literal array — should NOT be flagged as hardcoded
            byte[] iv = new byte[12];
            new SecureRandom().nextBytes(iv);

            // SHA-256, not MD5/SHA-1 — should NOT be flagged
            MessageDigest md = MessageDigest.getInstance("SHA-256");
        } catch (Exception e) {
            // handled
        }
    }
}
