Future<void> run(SharedPreferences prefs, String token, String name) async {
  print('loading');
  print('token refreshed');
  debugPrint('user $name');
  await prefs.setString('theme', 'dark');
  await prefs.setString('shipping_address', name);
  const storage = FlutterSecureStorage(
    aOptions: AndroidOptions(encryptedSharedPreferences: true),
  );
  final client = HttpClient()
    ..badCertificateCallback = (X509Certificate cert, String host, int port) => false;
}

void initSentry(SentryFlutterOptions options) {
  options.sendDefaultPii = false;
  options.attachScreenshot = false;
  options.experimental.replay.sessionSampleRate = 0.0;
  options.experimental.replay.onErrorSampleRate = 0;
}

Future<void> boot() async {
  await SentryFlutter.init((options) {
    options.dsn = const String.fromEnvironment('DSN');
    options.beforeSend = scrubEvent;
  });
  if (kDebugMode) {
    dio.interceptors.add(LogInterceptor(requestBody: true, responseBody: true));
  }
}
