const off = FlutterSecureStorage(
  aOptions: AndroidOptions(encryptedSharedPreferences: false),
);
const on = FlutterSecureStorage(
  aOptions: AndroidOptions(encryptedSharedPreferences:   true),
);
