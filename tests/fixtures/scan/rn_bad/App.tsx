import AsyncStorage from '@react-native-async-storage/async-storage';

export async function run(token: string) {
  await AsyncStorage.setItem('auth_token', token);
  await AsyncStorage.setItem(TOKEN_KEY, token);
  console.log('session', token);
  console.log(`token ${token}`);
  return <WebView originWhitelist={['*']} source={{ uri: url }} />;
}
