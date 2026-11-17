import 'dart:io';

Future<void> run(SharedPreferences prefs, String token, String name) async {
  await prefs.setString('auth_token', token);
  await prefs.setString(kPinKey, '1234');
  await prefs.setString('userPin', '1234');
  print('token=$token');
  debugPrint('session ' + token);
  print(token);
  const storage = FlutterSecureStorage();
  final client = HttpClient()
    ..badCertificateCallback = (X509Certificate cert, String host, int port) => true;
  final other = HttpClient()
    ..badCertificateCallback = (_, __, ___) {
      return true;
    };
}

void initSentry(SentryFlutterOptions options) {
  options.sendDefaultPii = true;
  options.attachScreenshot = true;
  options.experimental.replay.sessionSampleRate = 0.1;
  options.experimental.replay.onErrorSampleRate = 1.0;
  final cipher = Encrypter(AES(key, mode: AESMode.ecb));
}

Future<void> boot() async {
  await SentryFlutter.init((options) {
    options.dsn = const String.fromEnvironment('DSN');
  });
  dio.interceptors.add(LogInterceptor(requestBody: true, responseBody: true));
}
