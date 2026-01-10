# 🔐 Aplikacja Android do Odszyfrowywania Tokenów PGP

Natywna aplikacja Android napisana w Kotlinie do odszyfrowywania wiadomości PGP używając klucza prywatnego użytkownika.

## Funkcjonalności

- ✅ Wprowadzanie zaszyfrowanej wiadomości PGP
- ✅ Wprowadzanie klucza prywatnego PGP
- ✅ Odszyfrowywanie wiadomości
- ✅ Wyświetlanie wyniku w osobnym polu
- ✅ Kopiowanie wyniku do schowka
- ✅ Nowoczesny interfejs Material Design

## Wymagania

- Android Studio Hedgehog (2023.1.1) lub nowszy
- Android SDK 24+ (Android 7.0)
- JDK 8 lub nowszy

## Instalacja

1. Otwórz projekt w Android Studio
2. Zsynchronizuj pliki Gradle
3. Zbuduj projekt (Build > Make Project)
4. Uruchom na urządzeniu lub emulatorze

## Użycie

1. Wklej zaszyfrowaną wiadomość PGP w pierwsze pole
2. Wklej swój klucz prywatny PGP w drugie pole
3. Naciśnij przycisk "🔓 Odszyfruj"
4. Wynik pojawi się w dolnym polu
5. Użyj przycisku "📋 Kopiuj wynik" aby skopiować wynik do schowka

## Technologie

- **Kotlin** - język programowania
- **BouncyCastle** - biblioteka kryptograficzna do obsługi PGP
- **Material Design** - nowoczesny interfejs użytkownika
- **View Binding** - bezpieczne odwołania do widoków

## Struktura projektu

```
pgp_decrypt_native/
├── app/
│   ├── src/
│   │   ├── main/
│   │   │   ├── java/com/pgpdecrypt/native/
│   │   │   │   └── MainActivity.kt
│   │   │   ├── res/
│   │   │   │   ├── layout/
│   │   │   │   │   └── activity_main.xml
│   │   │   │   └── values/
│   │   │   │       └── strings.xml
│   │   │   └── AndroidManifest.xml
│   │   └── build.gradle
├── build.gradle
├── settings.gradle
└── README.md
```

## Bezpieczeństwo

- Aplikacja działa całkowicie lokalnie
- Klucze prywatne nie są przesyłane nigdzie
- Wszystkie operacje kryptograficzne wykonywane są na urządzeniu
- Brak połączenia z internetem (opcjonalne, można dodać)

## Rozwiązywanie problemów

### Błąd: "Nie znaleziono klucza prywatnego"
- Upewnij się, że wkleiłeś pełny klucz prywatny wraz z nagłówkami `-----BEGIN PGP PRIVATE KEY BLOCK-----` i `-----END PGP PRIVATE KEY BLOCK-----`

### Błąd: "Nieprawidłowy format wiadomości PGP"
- Sprawdź czy wiadomość zawiera nagłówki `-----BEGIN PGP MESSAGE-----` i `-----END PGP MESSAGE-----`
- Upewnij się, że wiadomość nie jest uszkodzona

### Błąd: "Nie można znaleźć odpowiedniego klucza do odszyfrowania"
- Upewnij się, że wiadomość została zaszyfrowana kluczem publicznym odpowiadającym Twojemu kluczowi prywatnemu

## Licencja

Projekt jest dostępny do użytku osobistego.

