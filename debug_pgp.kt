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
    println("=" * 60)
    println("DIAGNOSTYKA ODSZYFROWYWANIA PGP")
    println("=" * 60)
    
    val encryptedMessage = """-----BEGIN PGP MESSAGE-----

wf8AAAIMA5fR6mMLjEmeAQ/+KEc1GVnLKYp02sQCvxZ60sLz05uU+xhX8aWCdZGi
c/OeU3vnDOdNjeP/A+3fzrtsZ0ZbrRzmpTXs4xMG9QIJL57wUxRxO+EjRimTHgc1
ZGBstDs7hf2Cz6mvc7nvPkBeQB8DH/FdmOzxGOnwEIj2o7gGt5u0kbrvZur/jrd1
rMYCUWx5D1PDcYtowDxAug1Z/iimHHPTzmV/zvoLpQANMZfqPAGeJBpsc5hDBq27
zKS+I4CwlCi/qx/jfWrfYRnF34uvLQfbuOe6z2A2kGbcuVm3oar3ioAd8WWr77TS
oLEbyZY6WJAxIRKOMWW33GaDrB54rt5uHs9oUpSxQ59aJGSK80pyu0JYUCnR4vv0
rEkCUfmIPiigVwgJeS4PYkkCwotAuHdSw08Pu6JLerOHzS6QXRRdQlnsQrNx5bwm
qjFpYKKEUfuweupobggXaHu8EelQQ2TbsczTEtNRoV6MO4KSA0TlJIjxj99loAgj
bngKuYeK2piGNtQBtebsp0mWdWrj9xzQ+feNdqYaAUiRofHOWtnjRixCseambeXk
Wykl1KabyNCZcONbi4SMfesfIeAvPzBzPm6EzqxoCksMPj/9mPnjLAFYMumxqAi5
+qiKfGume4Pc7VLSceJZYlG5JtcPmbWbZN7A6kIGtBKnRg9XfLdaniRmNwk6Zxpa
7KzB/wAAAgwD8OYsHJkF6z4BD/479hFLsdAwDBh2YgettIsB591+1G4rNr2ESE5q
zasCrIzOFWLG6yyew9sPiw8pJ21Ktb4phOahkyFtydlpeOMEKI4M3XLYmfrdwxGv
U1eMKDG69eirdXCIxrAQ+wklT95wlkyuTJE86lHFg3Jmstbjx8E4ZwqYjOY+WHMc
mbcPEI/BcBUeeDBtd1ZJC+cK8ICSa/gTnYUSqFB+8DwsvZhctSjkhOXh/ek338Hh
Zcd/5OnftjDn7qU3aJdQkhvPH3joYB+rbHJa7bHqlR9CcDylHI9K3pQYIYeSEZIB
Acjsc/C3ELrHWoPFr8DcLM54mdBMVzJqiErJ55NrdEIp2xRjTDQvXHmmPZE1LOwz
PFP+ZZuVb82PGQZ6LBjdjawUuD/hKXxUFZuZf4xUY2gYssNuCZX59BhMQBUeY3S2
EUccIR9H20QZGPevT3kG4Cz5axadievMTCt6o1oIiyxAx5CMrprjarsKIj7EFAeA
L0zu/GhJjQs068P8GaXnL5vgNaUQpwCwq/JwelfKbn4s1XxM5fb6S2gUGTeckZDx
INGJ7cIl5xAr6YBrc/8w0AnmTHeA0xET9ZgupyOJpEiEdUV+Q6NO+murK+sPke+N
5/7d9Fwu6tSYLQFwI3NfWwBTXXXdx0N2p9RZsXYaAlJz7N67dAkZYju2Kwab8Qje
imPmsdL/AAAAXAGtPXaSIpV5MwqAlVpr0KkcTghaLbfVJy0G8+wfkOlkITuqu25T
77NqRe0MBOLY2SliDHad7kJlZ1fUjLtl+04g036PBbxXbX3CxTAYwOFMR/UJR9Hq
HZANM49D
=ygAj
-----END PGP MESSAGE-----"""

    val privateKeyText = """-----BEGIN PGP PRIVATE KEY BLOCK-----

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
=JBpp
-----END PGP PRIVATE KEY BLOCK-----"""
    
    try {
        // 1. Inicjalizacja BouncyCastle
        println("\n[1] Inicjalizacja BouncyCastle...")
        if (Security.getProvider("BC") == null) {
            Security.addProvider(BouncyCastleProvider())
        }
        println("✅ BouncyCastle zainicjalizowany")
        
        val fingerprintCalculator = BcKeyFingerprintCalculator()
        
        // 2. Analiza klucza prywatnego
        println("\n[2] Analiza klucza prywatnego...")
        val privateKeyStream = ByteArrayInputStream(privateKeyText.toByteArray(Charsets.UTF_8))
        val decoderStream = PGPUtil.getDecoderStream(privateKeyStream)
        val secretKeyRingCollection = PGPSecretKeyRingCollection(decoderStream, fingerprintCalculator)
        
        val availableKeyIDs = mutableListOf<Pair<Long, String>>()
        val keyRings = secretKeyRingCollection.keyRings
        var keyRingCount = 0
        while (keyRings.hasNext()) {
            keyRingCount++
            val keyRing = keyRings.next() as PGPSecretKeyRing
            val keys = keyRing.secretKeys
            var keyCount = 0
            while (keys.hasNext()) {
                keyCount++
                val key = keys.next() as PGPSecretKey
                val keyID = key.keyID
                val isMaster = key.isMasterKey
                val keyType = if (isMaster) "MASTER" else "SUBKEY"
                availableKeyIDs.add(Pair(keyID, keyType))
                println("  📌 Klucz #$keyCount: KeyID=${keyID.toString(16).uppercase()}, Typ=$keyType")
            }
            println("  KeyRing #$keyRingCount zawiera $keyCount kluczy")
        }
        println("✅ Znaleziono ${availableKeyIDs.size} kluczy prywatnych")
        
        // 3. Sprawdzenie czy klucz wymaga hasła
        println("\n[3] Sprawdzanie czy klucz wymaga hasła...")
        val testKey = secretKeyRingCollection.keyRings.next() as PGPSecretKeyRing
        val testSecretKey = testKey.secretKeys.next() as PGPSecretKey
        val digestCalculatorProvider = BcPGPDigestCalculatorProvider()
        try {
            testSecretKey.extractPrivateKey(
                BcPBESecretKeyDecryptorBuilder(digestCalculatorProvider)
                    .build(charArrayOf())
            )
            println("  ✅ Klucz NIE wymaga hasła")
        } catch (e: Exception) {
            println("  🔐 Klucz WYMAGA hasła: ${e.message}")
        }
        
        // 4. Analiza wiadomości zaszyfrowanej
        println("\n[4] Analiza wiadomości zaszyfrowanej...")
        val encryptedStream = ByteArrayInputStream(encryptedMessage.toByteArray(Charsets.UTF_8))
        val encryptedDecoderStream = PGPUtil.getDecoderStream(encryptedStream)
        val pgpObjectFactory = PGPObjectFactory(encryptedDecoderStream, fingerprintCalculator)
        
        var encryptedDataList: PGPEncryptedDataList? = null
        var obj: Any? = pgpObjectFactory.nextObject()
        var objectCount = 0
        
        while (obj != null) {
            objectCount++
            val objType = obj.javaClass.simpleName
            println("  Obiekt #$objectCount: $objType")
            
            when (obj) {
                is PGPEncryptedDataList -> {
                    encryptedDataList = obj
                    println("  ✅ Znaleziono PGPEncryptedDataList")
                    break
                }
                else -> {
                    obj = try {
                        pgpObjectFactory.nextObject()
                    } catch (e: Exception) {
                        null
                    }
                }
            }
        }
        
        if (encryptedDataList == null) {
            throw Exception("Nie znaleziono PGPEncryptedDataList")
        }
        
        // 5. Analiza zaszyfrowanych danych
        println("\n[5] Analiza zaszyfrowanych danych...")
        val encryptedDataObjects = encryptedDataList.encryptedDataObjects
        val encryptedKeyIDs = mutableListOf<Long>()
        
        while (encryptedDataObjects.hasNext()) {
            val encryptedDataObj = encryptedDataObjects.next()
            if (encryptedDataObj is PGPPublicKeyEncryptedData) {
                val keyID = encryptedDataObj.keyID
                encryptedKeyIDs.add(keyID)
                println("  🔒 Zaszyfrowane KeyID: ${keyID.toString(16).uppercase()}")
            }
        }
        println("✅ Znaleziono ${encryptedKeyIDs.size} zaszyfrowanych KeyID")
        
        // 6. Dopasowanie kluczy
        println("\n[6] Dopasowanie kluczy...")
        var matched = false
        for ((keyID, keyType) in availableKeyIDs) {
            val keyIDHex = keyID.toString(16).uppercase()
            if (encryptedKeyIDs.contains(keyID)) {
                println("  ✅ DOPASOWANIE: KeyID=$keyIDHex ($keyType) jest w zaszyfrowanych danych!")
                matched = true
            } else {
                println("  ❌ Brak dopasowania: KeyID=$keyIDHex ($keyType)")
            }
        }
        
        if (!matched) {
            println("  ⚠️ UWAGA: Żaden klucz prywatny nie pasuje do zaszyfrowanych KeyID!")
            println("  To może być problem - aplikacja spróbuje użyć pierwszego dostępnego klucza")
        }
        
        println("\n" + "=" * 60)
        println("PODSUMOWANIE:")
        println("=" * 60)
        println("Klucze prywatne: ${availableKeyIDs.size}")
        println("Zaszyfrowane KeyID: ${encryptedKeyIDs.size}")
        println("Dopasowanie: ${if (matched) "✅ TAK" else "❌ NIE"}")
        println("=" * 60)
        
    } catch (e: Exception) {
        println("\n❌ BŁĄD:")
        println(e.message)
        e.printStackTrace()
    }
}

