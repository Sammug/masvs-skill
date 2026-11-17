import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:local_auth/local_auth.dart';

class Session {
  static const _storage = FlutterSecureStorage(
    aOptions: AndroidOptions(encryptedSharedPreferences: true),
  );
  final _localAuth = LocalAuthentication();

  Future<void> save(String refreshToken) =>
      _storage.write(key: 'refresh_token', value: refreshToken);

  // Called on app launch: biometric prompt, then reuse the stored refresh token.
  Future<String?> resume() async {
    final ok = await _localAuth.authenticate(localizedReason: 'Unlock Example App');
    if (!ok) return null;
    return _storage.read(key: 'refresh_token');
  }

  Future<void> logout() => _storage.delete(key: 'refresh_token');
}
