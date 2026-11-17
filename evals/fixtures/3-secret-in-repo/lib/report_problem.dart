import 'package:http/http.dart' as http;

import 'config.dart';

Future<void> reportProblem(String text) {
  return http.post(
    Uri.parse('https://git.example.invalid/api/v4/projects/1/issues'),
    headers: {'PRIVATE-TOKEN': AppConfig.issueTrackerToken},
    body: {'title': 'In-app report', 'description': text},
  );
}
