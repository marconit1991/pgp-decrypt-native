#!/bin/bash

# Skrypt do uruchomienia debug_decrypt.kt lokalnie
# Wymaga: kotlinc (Kotlin Compiler) i BouncyCastle w classpath

echo "🔐 Uruchamianie debugu deszyfrowania PGP..."
echo ""

# Sprawdź czy kotlinc jest dostępny
if ! command -v kotlinc &> /dev/null; then
    echo "❌ Błąd: kotlinc nie jest dostępny"
    echo ""
    echo "Aby uruchomić ten skrypt, potrzebujesz:"
    echo "1. Zainstalować Kotlin Compiler:"
    echo "   - Pobierz z: https://github.com/JetBrains/kotlin/releases"
    echo "   - Lub użyj SDKMAN: sdk install kotlin"
    echo ""
    echo "2. Pobierz BouncyCastle JAR:"
    echo "   - bcprov-jdk15on-1.70.jar"
    echo "   - bcpg-jdk15on-1.70.jar"
    echo "   - bcpkix-jdk15on-1.70.jar"
    echo "   Z: https://www.bouncycastle.org/download/"
    echo ""
    echo "3. Uruchom:"
    echo "   kotlinc -cp bcprov-jdk15on-1.70.jar:bcpg-jdk15on-1.70.jar:bcpkix-jdk15on-1.70.jar debug_decrypt.kt -include-runtime -d debug_decrypt.jar"
    echo "   java -cp debug_decrypt.jar:bcprov-jdk15on-1.70.jar:bcpg-jdk15on-1.70.jar:bcpkix-jdk15on-1.70.jar MainKt"
    exit 1
fi

# Sprawdź czy pliki BouncyCastle istnieją
BCPROV="bcprov-jdk15on-1.70.jar"
BCPG="bcpg-jdk15on-1.70.jar"
BCPKIX="bcpkix-jdk15on-1.70.jar"

if [ ! -f "$BCPROV" ] || [ ! -f "$BCPG" ] || [ ! -f "$BCPKIX" ]; then
    echo "⚠️  Pliki BouncyCastle nie znalezione w bieżącym katalogu"
    echo ""
    echo "Pobierz je z: https://www.bouncycastle.org/download/"
    echo "Potrzebne pliki:"
    echo "  - $BCPROV"
    echo "  - $BCPG"
    echo "  - $BCPKIX"
    echo ""
    echo "Lub użyj wget:"
    echo "  wget https://repo1.maven.org/maven2/org/bouncycastle/bcprov-jdk15on/1.70/$BCPROV"
    echo "  wget https://repo1.maven.org/maven2/org/bouncycastle/bcpg-jdk15on/1.70/$BCPG"
    echo "  wget https://repo1.maven.org/maven2/org/bouncycastle/bcpkix-jdk15on/1.70/$BCPKIX"
    exit 1
fi

# Kompiluj
echo "📦 Kompilowanie debug_decrypt.kt..."
kotlinc -cp "$BCPROV:$BCPG:$BCPKIX" debug_decrypt.kt -include-runtime -d debug_decrypt.jar

if [ $? -ne 0 ]; then
    echo "❌ Błąd kompilacji"
    exit 1
fi

echo "✅ Kompilacja zakończona"
echo ""
echo "🚀 Uruchamianie..."
echo ""

# Uruchom
java -cp "debug_decrypt.jar:$BCPROV:$BCPG:$BCPKIX" MainKt

# Usuń plik JAR po zakończeniu (opcjonalnie)
# rm -f debug_decrypt.jar

