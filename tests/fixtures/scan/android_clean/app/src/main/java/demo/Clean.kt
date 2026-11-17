package demo

class Clean {
    fun run(token: String, prefs: SharedPreferences) {
        val state = Environment.getExternalStorageState()
        val a = Cipher.getInstance("AES/GCM/NoPadding")
        val d = MessageDigest.getInstance("SHA-256")
        webView.settings.javaScriptEnabled = false
        Log.d(TAG, "loading")
        Log.d(TAG, "token refreshed")
        Log.d(tokenTag, "started")
        prefs.edit().putString("theme", "dark").apply()
    }
}

val strict = object : X509TrustManager {
    override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
        delegate.checkServerTrusted(chain, authType)
    }
}
