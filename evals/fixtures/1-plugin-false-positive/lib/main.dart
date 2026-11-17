import 'package:cached_network_image/cached_network_image.dart';
import 'package:flutter/material.dart';

void main() => runApp(const ExampleApp());

class ExampleApp extends StatelessWidget {
  const ExampleApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Example App',
      home: Scaffold(
        body: CachedNetworkImage(imageUrl: 'https://cdn.example.invalid/banner.png'),
      ),
    );
  }
}
