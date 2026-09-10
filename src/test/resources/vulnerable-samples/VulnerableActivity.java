package com.example.vulnerableapp;

import android.app.Activity;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.os.Environment;
import android.webkit.WebSettings;
import android.webkit.WebView;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import java.io.File;
import java.security.MessageDigest;

/**
 * Deliberately vulnerable sample, modeled loosely on the kinds of patterns
 * found in InsecureBankv2, used to validate detector recall.
 */
public class VulnerableActivity extends Activity {

    // --- HARDCODED_SECRET: known-format signature match ---
    private static final String GOOGLE_MAPS_API_KEY = "AIzaSyD-9tSrke72PouQMnMX-a7eZSW0jkFMBWY";

    // --- HARDCODED_SECRET: name+entropy heuristic ---
    private String backendAuthToken = "9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c";

    // --- WEAK_CRYPTO: hardcoded IV ---
    private static final byte[] IV_BYTES = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                             0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // --- INSECURE_STORAGE: world-readable/writable SharedPreferences ---
        SharedPreferences prefs = getSharedPreferences("user_session", Context.MODE_WORLD_READABLE);
        SharedPreferences.Editor editor = prefs.edit();
        editor.putString("auth_token", backendAuthToken);
        editor.commit();

        // --- INSECURE_STORAGE: writing to external storage ---
        File logFile = new File(Environment.getExternalStorageDirectory(), "app_debug.log");

        setupWebView();
        encryptWithEcb();
        hashPasswordWithMd5("hunter2");
    }

    private void setupWebView() {
        WebView webView = new WebView(this);
        WebSettings settings = webView.getSettings();

        // --- WEBVIEW_MISCONFIG: JS enabled + bridge exposed ---
        settings.setJavaScriptEnabled(true);
        webView.addJavascriptInterface(new Object(), "AndroidBridge");

        // --- WEBVIEW_MISCONFIG: mixed content always allow ---
        settings.setMixedContentMode(WebSettings.MIXED_CONTENT_ALWAYS_ALLOW);
    }

    private byte[] encryptWithEcb() {
        try {
            // --- WEAK_CRYPTO: ECB mode ---
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            IvParameterSpec ivSpec = new IvParameterSpec(IV_BYTES);
            return new byte[0];
        } catch (Exception e) {
            return null;
        }
    }

    private String hashPasswordWithMd5(String password) {
        try {
            // --- WEAK_CRYPTO: MD5 used for what looks like a security purpose ---
            MessageDigest md = MessageDigest.getInstance("MD5");
            return new String(md.digest(password.getBytes()));
        } catch (Exception e) {
            return null;
        }
    }
}
