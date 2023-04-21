# Karma Coin Authenticator
A Firebase services proxy micro service.
Securely communicates

## Setup
```bash
dart pub global activate protoc_plugin
dart pub get
```

## Running in dev mode
```bash
dart lib/src/server.dart
```

## Building 
```bash
dart compile exe lib/src/server.dart -o ./authenticator.exe
```

## Running
Use creds.json to set firebase secrets.
```
./authenticator.exe
```

Copyright (c) 2022 by the KarmaCoin Authors. This work is licensed under the [KarmaCoin License](https://github.com/karma-coin/.github/blob/main/LICENSE).
