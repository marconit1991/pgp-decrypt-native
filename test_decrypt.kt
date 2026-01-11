import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openpgp.*
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.security.Security

fun main() {
    println("🔐 Test odszyfrowywania PGP")
    println("Wklej zaszyfrowaną wiadomość PGP (zakończ pustą linią):")
    
    val encryptedMessage = buildString {
        while (true) {
            val line = readLine() ?: break
            if (line.isEmpty()) break
            append(line).append("\n")
        }
    }.trim()
    
    println("\nWklej klucz prywatny PGP (zakończ pustą linią):")
    val privateKeyText = buildString {
        while (true) {
            val line = readLine() ?: break
            if (line.isEmpty()) break
            append(line).append("\n")
        }
    }.trim()
    
    println("\nCzy klucz wymaga hasła? (t/n):")
    val needsPassword = readLine()?.lowercase() == "t"
    val password = if (needsPassword) {
        print("Wprowadź hasło: ")
        readLine() ?: ""
    } else {
        ""
    }
    
    try {
        val result = decryptPGP(encryptedMessage, privateKeyText, password)
        println("\n✅ SUKCES! Odszyfrowana wiadomość:")
        println("=" * 50)
        println(result)
        println("=" * 50)
    } catch (e: Exception) {
        println("\n❌ BŁĄD:")
        println(e.message)
        e.printStackTrace()
    }
}

fun decryptPGP(encryptedMessage: String, privateKeyText: String, password: String = ""): String {
    // Dodaj BouncyCastle provider
    if (Security.getProvider("BC") == null) {
        Security.addProvider(BouncyCastleProvider())
    }
    
    val fingerprintCalculator = BcKeyFingerprintCalculator()
    
    // Wczytaj klucz prywatny
    val privateKeyStream = ByteArrayInputStream(privateKeyText.toByteArray(Charsets.UTF_8))
    val decoderStream = PGPUtil.getDecoderStream(privateKeyStream)
    val secretKeyRingCollection = PGPSecretKeyRingCollection(decoderStream, fingerprintCalculator)
    
    // Wczytaj zaszyfrowaną wiadomość
    val encryptedStream = ByteArrayInputStream(encryptedMessage.toByteArray(Charsets.UTF_8))
    val encryptedDecoderStream = PGPUtil.getDecoderStream(encryptedStream)
    val pgpObjectFactory = PGPObjectFactory(encryptedDecoderStream, fingerprintCalculator)
    
    // Znajdź PGPEncryptedDataList
    var encryptedDataList: PGPEncryptedDataList? = null
    var obj: Any? = pgpObjectFactory.nextObject()
    
    while (obj != null) {
        when (obj) {
            is PGPEncryptedDataList -> {
                encryptedDataList = obj
                break
            }
            is PGPOnePassSignatureList -> {
                obj = pgpObjectFactory.nextObject()
                continue
            }
            else -> {
                obj = try {
                    pgpObjectFactory.nextObject()
                } catch (e: Exception) {
                    null
                }
                continue
            }
        }
    }
    
    if (encryptedDataList == null) {
        throw Exception("Nie znaleziono zaszyfrowanych danych")
    }
    
    // Znajdź PGPPublicKeyEncryptedData i jego KeyID
    var publicKeyEncryptedData: PGPPublicKeyEncryptedData? = null
    val encryptedDataObjects = encryptedDataList.encryptedDataObjects
    while (encryptedDataObjects.hasNext()) {
        val encryptedDataObj = encryptedDataObjects.next()
        if (encryptedDataObj is PGPPublicKeyEncryptedData) {
            publicKeyEncryptedData = encryptedDataObj
            break
        }
    }
    
    if (publicKeyEncryptedData == null) {
        throw Exception("Nie znaleziono zaszyfrowanych danych kluczem publicznym")
    }
    
    val requiredKeyID = publicKeyEncryptedData.keyID
    println("Szukam klucza z KeyID: $requiredKeyID")
    
    // Znajdź pasujący klucz prywatny
    var secretKey: PGPSecretKey? = null
    val keyRings = secretKeyRingCollection.keyRings
    while (keyRings.hasNext()) {
        val keyRing = keyRings.next() as PGPSecretKeyRing
        val keys = keyRing.secretKeys
        while (keys.hasNext()) {
            val key = keys.next() as PGPSecretKey
            val keyID = key.keyID
            println("Sprawdzam klucz z KeyID: $keyID")
            if (keyID == requiredKeyID) {
                secretKey = key
                println("✅ Znaleziono pasujący klucz!")
                break
            }
        }
        if (secretKey != null) break
    }
    
    if (secretKey == null) {
        println("⚠️ Nie znaleziono pasującego KeyID, używam pierwszego dostępnego klucza")
        val keyRings2 = secretKeyRingCollection.keyRings
        while (keyRings2.hasNext()) {
            val keyRing = keyRings2.next() as PGPSecretKeyRing
            val keys = keyRing.secretKeys
            while (keys.hasNext()) {
                val key = keys.next() as PGPSecretKey
                secretKey = key
                println("Używam klucza z KeyID: ${key.keyID}")
                break
            }
            if (secretKey != null) break
        }
    }
    
    if (secretKey == null) {
        throw Exception("Nie znaleziono klucza prywatnego")
    }
    
    // Wyodrębnij klucz prywatny
    val digestCalculatorProvider = BcPGPDigestCalculatorProvider()
    val pgpPrivateKey = secretKey.extractPrivateKey(
        BcPBESecretKeyDecryptorBuilder(digestCalculatorProvider)
            .build(password.toCharArray())
    )
    
    // Odszyfruj
    val dataDecryptorFactory = BcPublicKeyDataDecryptorFactory(pgpPrivateKey)
    val encryptedInputStream = publicKeyEncryptedData.getDataStream(dataDecryptorFactory)
    val literalDataFactory = PGPObjectFactory(encryptedInputStream, fingerprintCalculator)
    
    var decryptedObj: Any? = literalDataFactory.nextObject()
    var decryptedData: ByteArray? = null
    
    while (decryptedObj != null && decryptedData == null) {
        when (decryptedObj) {
            is PGPLiteralData -> {
                decryptedData = readLiteralData(decryptedObj)
                break
            }
            is PGPCompressedData -> {
                val compressedFactory = PGPObjectFactory(decryptedObj.dataStream, fingerprintCalculator)
                decryptedObj = compressedFactory.nextObject()
                continue
            }
            else -> {
                decryptedObj = try {
                    literalDataFactory.nextObject()
                } catch (e: Exception) {
                    null
                }
            }
        }
    }
    
    if (decryptedData == null) {
        throw Exception("Nie znaleziono danych do odszyfrowania")
    }
    
    return String(decryptedData, Charsets.UTF_8)
}

fun readLiteralData(literalData: PGPLiteralData): ByteArray {
    val inputStream = literalData.inputStream
    val outputStream = ByteArrayOutputStream()
    
    val buffer = ByteArray(4096)
    var bytesRead: Int
    while (true) {
        bytesRead = inputStream.read(buffer)
        if (bytesRead == -1) break
        outputStream.write(buffer, 0, bytesRead)
    }
    
    return outputStream.toByteArray()
}

