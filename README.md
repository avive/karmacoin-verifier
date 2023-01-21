# Karma Coin Verifier
An implementation of the Karma Coin verifier api service in Dart.

## Running in dev mode
From the project root dir:
```bash
dart lib/src/server.dart
```

## Building 
From the project root dir:
```bash
dart compile exe lib/src/server.dart -o ./verifier.exe
```

## Running
```
envoy -c envoy/config.yaml
./verifier.exe
```

Copyright (c) 2022 by the KarmaCoin Authors. This work is licensed under the [KarmaCoin License](https://github.com/karma-coin/.github/blob/main/LICENSE).
