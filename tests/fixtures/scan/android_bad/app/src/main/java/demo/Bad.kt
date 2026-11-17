package demo

class Bad {
    fun run(ctx: Context, token: String, prefs: SharedPreferences) {
        val dir = Environment.getExternalStorageDirectory()
        ctx.openFileOutput("x", Context.MODE_WORLD_READABLE)
        val a = Cipher.getInstance("AES/ECB/PKCS5Padding")
        val b = Cipher.getInstance("AES/CBC/PKCS5Padding")
        val c = Cipher.getInstance("DES")
        val d = MessageDigest.getInstance("MD5")
        val e = MessageDigest.getInstance("SHA-1")
        webView.settings.javaScriptEnabled = true
        webView.addJavascriptInterface(Bridge(), "bridge")
        Log.d(TAG, "token=" + token)
        Log.i(TAG, "pw $password")
        prefs.edit().putString("auth_token", token).apply()
    }
}

val trustAll = object : X509TrustManager {
    override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
    override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}
    override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
}
val anyHost = HostnameVerifier { _, _ -> true }
