# 🔐 Odszyfruj Token PGP

Natywna aplikacja Android napisana w Kotlinie do odszyfrowywania wiadomości PGP używając klucza prywatnego użytkownika.

## Funkcjonalności

- ✅ Wprowadzanie zaszyfrowanej wiadomości PGP
- ✅ Wprowadzanie klucza prywatnego PGP (wklejanie lub wczytywanie z pliku)
- ✅ Obsługa kluczy prywatnych chronionych hasłem
- ✅ Automatyczne dopasowywanie kluczy (główny klucz i subkey)
- ✅ Odszyfrowywanie wiadomości
- ✅ Wyświetlanie wyniku jako "Token"
- ✅ Kopiowanie tokenu do schowka
- ✅ Nowoczesny interfejs Material Design (ciemny motyw, czerwone akcenty)

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
2. Wklej swój klucz prywatny PGP w drugie pole (lub użyj przycisku "📁 Wczytaj z pliku")
3. Jeśli klucz wymaga hasła, pojawi się dialog do wprowadzenia hasła
4. Naciśnij przycisk "🔓 Odszyfruj"
5. Token pojawi się w dolnym polu
6. Użyj przycisku "📋 Kopiuj wynik" aby skopiować token do schowka

## Kompilacja

### Lokalnie (Android Studio)
1. Otwórz projekt w Android Studio
2. Zsynchronizuj pliki Gradle
3. Zbuduj projekt (Build > Make Project)
4. Uruchom na urządzeniu lub emulatorze

### Automatycznie (GitHub Actions)
Aplikacja jest automatycznie kompilowana przy każdym pushu do repozytorium:
1. Prześlij zmiany do GitHub
2. Przejdź do zakładki "Actions" w repozytorium
3. Pobierz skompilowany APK z artefaktów

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
│   │   │   ├── java/com/pgpdecrypt/app/
│   │   │   │   └── MainActivity.kt
│   │   │   ├── res/
│   │   │   │   ├── layout/
│   │   │   │   │   └── activity_main.xml
│   │   │   │   └── values/
│   │   │   │       ├── strings.xml
│   │   │   │       ├── colors.xml
│   │   │   │       └── themes.xml
│   │   │   └── AndroidManifest.xml
│   │   └── build.gradle
├── .github/
│   └── workflows/
│       └── build-apk.yml
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
- Aplikacja automatycznie próbuje dopasować główny klucz i subkey

### Błąd: "Klucz prywatny wymaga hasła"
- Jeśli klucz jest chroniony hasłem, aplikacja automatycznie wyświetli dialog do wprowadzenia hasła
- Upewnij się, że wprowadzasz poprawne hasło

### Błąd: "block incorrect" lub "Błąd odszyfrowywania danych sesji"
- Sprawdź czy klucz prywatny pasuje do wiadomości (KeyID musi się zgadzać)
- Upewnij się, że wprowadziłeś poprawne hasło (jeśli klucz jest chroniony)
- Sprawdź czy wiadomość nie jest uszkodzona

## Licencja

Projekt jest dostępny do użytku osobistego.



