package com.example.vulnapp;

import android.content.Context;
import android.content.SharedPreferences;

public class Session {
    void save(Context ctx, String user, String authToken) {
        SharedPreferences prefs = ctx.getSharedPreferences("session", Context.MODE_WORLD_READABLE);
        prefs.edit()
            .putString("username", user)
            .putString("auth_token", authToken)
            .apply();
    }
}
