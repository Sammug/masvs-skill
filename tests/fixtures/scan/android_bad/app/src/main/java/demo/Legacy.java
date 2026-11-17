package demo;

public class Legacy {
    void run() throws Exception {
        Cipher c = Cipher.getInstance("AES");
        TrustManager[] all = new TrustManager[] { new X509TrustManager() {
            public void checkServerTrusted(X509Certificate[] chain, String authType) {
                // trust everything
            }
        } };
        HttpsURLConnection.setDefaultHostnameVerifier(SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);
        settings.setAllowFileAccessFromFileURLs(true);
    }
}
