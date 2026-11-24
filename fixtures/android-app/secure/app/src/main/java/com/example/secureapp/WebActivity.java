package com.example.secureapp;

import android.webkit.WebSettings;
import android.webkit.WebView;

public class WebActivity {
    void configure(WebView view) {
        WebSettings settings = view.getSettings();
        settings.setJavaScriptEnabled(true);
        settings.setAllowFileAccess(false);
        view.loadUrl("https://example.com/app");
    }
}
