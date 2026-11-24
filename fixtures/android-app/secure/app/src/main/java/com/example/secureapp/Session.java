package com.example.secureapp;

import android.content.Context;
import android.content.SharedPreferences;
import androidx.security.crypto.EncryptedSharedPreferences;
import androidx.security.crypto.MasterKey;

public class Session {
    void save(Context ctx, MasterKey key, String authToken) throws Exception {
        SharedPreferences prefs = EncryptedSharedPreferences.create(ctx, "session", key,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM);
        prefs.edit().putString("auth_token", authToken).apply();
        ctx.getSharedPreferences("ui", Context.MODE_PRIVATE);
    }
}
