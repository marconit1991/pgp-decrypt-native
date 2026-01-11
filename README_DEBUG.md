# 🔍 Debug Mechanizmu Deszyfrowania PGP

Ten katalog zawiera szczegółowy skrypt debugowy, który krok po kroku pokazuje jak działa mechanizm deszyfrowania wiadomości PGP.

## Co pokazuje skrypt?

Skrypt `debug_decrypt.kt` analizuje i wyświetla:

1. **Inicjalizację BouncyCastle** - dodanie providera kryptograficznego
2. **Parsowanie klucza prywatnego** - analiza wszystkich kluczy (master + subkey)
3. **Sprawdzenie hasła** - czy klucz wymaga hasła do odszyfrowania
4. **Parsowanie wiadomości** - analiza struktury zaszyfrowanej wiadomości PGP
5. **Analizę zaszyfrowanych danych** - wszystkie KeyID w wiadomości
6. **Dopasowywanie kluczy** - porównanie KeyID z klucza i wiadomości
7. **Wyodrębnianie klucza prywatnego** - ekstrakcja z hasłem lub bez
8. **Odszyfrowywanie danych sesji** - dekodowanie klucza sesji
9. **Czytanie danych literalnych** - odczyt odszyfrowanej treści

## Jak uruchomić?

### Opcja 1: Użyj skryptu pomocniczego (zalecane)

```bash
./run_debug.sh
```

Skrypt automatycznie:
- Sprawdzi czy masz `kotlinc`
- Pobierze biblioteki BouncyCastle jeśli brakuje
- Skompiluje i uruchomi debug

### Opcja 2: Ręczna kompilacja

1. **Pobierz biblioteki BouncyCastle:**
```bash
wget https://repo1.maven.org/maven2/org/bouncycastle/bcprov-jdk15on/1.70/bcprov-jdk15on-1.70.jar
wget https://repo1.maven.org/maven2/org/bouncycastle/bcpg-jdk15on/1.70/bcpg-jdk15on-1.70.jar
wget https://repo1.maven.org/maven2/org/bouncycastle/bcpkix-jdk15on/1.70/bcpkix-jdk15on-1.70.jar
```

2. **Skompiluj:**
```bash
kotlinc -cp bcprov-jdk15on-1.70.jar:bcpg-jdk15on-1.70.jar:bcpkix-jdk15on-1.70.jar \
        debug_decrypt.kt -include-runtime -d debug_decrypt.jar
```

3. **Uruchom:**
```bash
java -cp debug_decrypt.jar:bcprov-jdk15on-1.70.jar:bcpg-jdk15on-1.70.jar:bcpkix-jdk15on-1.70.jar MainKt
```

## Wymagania

- **Kotlin Compiler** (`kotlinc`)
  - Pobierz z: https://github.com/JetBrains/kotlin/releases
  - Lub użyj SDKMAN: `sdk install kotlin`
  
- **Java JDK 8+**
  - Sprawdź: `java -version`

- **Biblioteki BouncyCastle 1.70**
  - Automatycznie pobierane przez `run_debug.sh`
  - Lub ręcznie z Maven Central

## Przykładowy output

```
================================================================================
🔐 SZCZEGÓŁOWA ANALIZA MECHANIZMU DESZYFROWANIA PGP
================================================================================

================================================================================
KROK 1: INICJALIZACJA BOUNCYCASTLE
================================================================================
✅ Dodano BouncyCastle provider
✅ Utworzono BcKeyFingerprintCalculator

================================================================================
KROK 2: PARSOWANIE KLUCZA PRYWATNEGO
================================================================================
📄 Długość klucza prywatnego: 3456 znaków
✅ Znaleziono nagłówek PGP w kluczu prywatnym
✅ Utworzono strumień dekodujący dla klucza prywatnego
✅ Załadowano kolekcję kluczy prywatnych (PGPSecretKeyRingCollection)

📋 ANALIZA KLUCZY PRYWATNYCH:
  🔑 KeyRing #1:
    📌 Klucz #1:
       KeyID: 0xF0E62C1C9905EB3E (decimal: 17345678901234567890)
       Typ: MASTER
       Algorytm: 1
    📌 Klucz #2:
       KeyID: 0x97D1EA630B8C499E (decimal: 10987654321098765432)
       Typ: SUBKEY
       Algorytm: 1

[... więcej szczegółów ...]

✅ SUKCES! ODSZYFROWANA WIADOMOŚĆ:
================================================================================
Twoja odszyfrowana wiadomość tutaj...
================================================================================
```

## Modyfikacja hasła

Jeśli klucz wymaga hasła, edytuj plik `debug_decrypt.kt` i zmień:

```kotlin
val password = "" // Wprowadź hasło tutaj jeśli klucz jest chroniony
```

na:

```kotlin
val password = "twoje_haslo" // Wprowadź hasło tutaj jeśli klucz jest chroniony
```

## Zastosowanie

Ten skrypt jest przydatny do:
- Zrozumienia jak działa deszyfrowanie PGP
- Debugowania problemów z dopasowywaniem kluczy
- Analizy struktury wiadomości PGP
- Testowania przed wdrożeniem w aplikacji Android


