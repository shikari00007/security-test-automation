package com.example.vulnapp;

import android.webkit.WebSettings;
import android.webkit.WebView;

public class WebActivity {
    // settings.setAllowFileAccess(true);  (commented out example, must be ignored)
    void configure(WebView view) {
        WebSettings settings = view.getSettings();
        settings.setJavaScriptEnabled(true);
        settings.setAllowFileAccess(true);
        view.addJavascriptInterface(new Bridge(), "bridge");
        view.loadUrl("https://example.com/app");
    }
    static class Bridge {}
}
