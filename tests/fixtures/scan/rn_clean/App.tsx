import AsyncStorage from '@react-native-async-storage/async-storage';

export async function run(token: string) {
  await AsyncStorage.setItem('theme', 'dark');
  console.log('loading');
  console.log('token refreshed');
  __DEV__ && console.log('session', token);
  return <WebView originWhitelist={['https://*']} source={{ uri: url }} />;
}
