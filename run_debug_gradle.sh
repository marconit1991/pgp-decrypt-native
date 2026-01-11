#!/bin/bash

# Uruchomienie debugu używając Gradle (nie wymaga kotlinc)

cd "$(dirname "$0")"

echo "🔐 Uruchamianie debugu deszyfrowania PGP (używając Gradle)..."
echo ""

# Sprawdź czy gradlew jest dostępny
if [ ! -f "gradlew" ]; then
    echo "❌ Błąd: gradlew nie znaleziony"
    exit 1
fi

# Upewnij się że gradlew jest wykonywalny
chmod +x gradlew

echo "📦 Kompilowanie i uruchamianie debug_decrypt.kt..."
echo ""

# Uruchom używając build_debug.gradle
./gradlew -b build_debug.gradle runDebug

