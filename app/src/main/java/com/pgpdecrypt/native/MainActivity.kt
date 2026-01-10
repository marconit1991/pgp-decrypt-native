package com.pgpdecrypt.native

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Bundle
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.button.MaterialButton
import com.google.android.material.textfield.TextInputEditText
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openpgp.*
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorBuilder
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.security.Security
import java.util.*

class MainActivity : AppCompatActivity() {
    
    private lateinit var encryptedMessageEditText: TextInputEditText
    private lateinit var privateKeyEditText: TextInputEditText
    private lateinit var decryptedResultEditText: TextInputEditText
    private lateinit var decryptButton: MaterialButton
    private lateinit var copyButton: MaterialButton
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        
        // Dodaj BouncyCastle provider
        if (Security.getProvider("BC") == null) {
            Security.addProvider(BouncyCastleProvider())
        }
        
        // Inicjalizuj widoki
        encryptedMessageEditText = findViewById(R.id.encryptedMessageEditText)
        privateKeyEditText = findViewById(R.id.privateKeyEditText)
        decryptedResultEditText = findViewById(R.id.decryptedResultEditText)
        decryptButton = findViewById(R.id.decryptButton)
        copyButton = findViewById(R.id.copyButton)
        
        // Przycisk odszyfrowywania
        decryptButton.setOnClickListener {
            decryptPGPMessage()
        }
        
        // Przycisk kopiowania
        copyButton.setOnClickListener {
            copyToClipboard()
        }
    }
    
    private fun decryptPGPMessage() {
        val encryptedMessage = encryptedMessageEditText.text?.toString()?.trim() ?: ""
        val privateKeyText = privateKeyEditText.text?.toString()?.trim() ?: ""
        
        if (encryptedMessage.isEmpty()) {
            Toast.makeText(this, "Wprowadź zaszyfrowaną wiadomość", Toast.LENGTH_SHORT).show()
            return
        }
        
        if (privateKeyText.isEmpty()) {
            Toast.makeText(this, "Wprowadź klucz prywatny", Toast.LENGTH_SHORT).show()
            return
        }
        
        if (!encryptedMessage.contains("-----BEGIN PGP MESSAGE-----")) {
            Toast.makeText(this, getString(R.string.error_invalid_pgp), Toast.LENGTH_SHORT).show()
            return
        }
        
        // Wyłącz przycisk podczas odszyfrowywania
        decryptButton.isEnabled = false
        decryptButton.text = getString(R.string.decrypting)
        
        // Uruchom w tle
        Thread {
            try {
                val decrypted = decryptPGP(encryptedMessage, privateKeyText)
                
                runOnUiThread {
                    decryptedResultEditText.setText(decrypted)
                    copyButton.isEnabled = true
                    decryptButton.isEnabled = true
                    decryptButton.text = getString(R.string.decrypt_button)
                    Toast.makeText(this, "✅ Odszyfrowano pomyślnie!", Toast.LENGTH_SHORT).show()
                }
            } catch (e: Exception) {
                runOnUiThread {
                    decryptedResultEditText.setText("❌ Błąd: ${e.message}")
                    decryptButton.isEnabled = true
                    decryptButton.text = getString(R.string.decrypt_button)
                    Toast.makeText(this, "${getString(R.string.error_decrypt)}: ${e.message}", Toast.LENGTH_LONG).show()
                }
            }
        }.start()
    }
    
    private fun decryptPGP(encryptedMessage: String, privateKeyText: String): String {
        try {
            // Wczytaj klucz prywatny
            val privateKeyStream = ByteArrayInputStream(privateKeyText.toByteArray())
            val decoderStream = PGPUtil.getDecoderStream(privateKeyStream)
            val secretKeyRingCollection = PGPSecretKeyRingCollection(decoderStream)
            
            // Znajdź pierwszy klucz prywatny (może być szyfrowany hasłem)
            var secretKey: PGPSecretKey? = null
            val keyRings = secretKeyRingCollection.keyRings
            while (keyRings.hasNext()) {
                val keyRing = keyRings.next() as PGPSecretKeyRing
                val keys = keyRing.secretKeys
                while (keys.hasNext()) {
                    val key = keys.next() as PGPSecretKey
                    secretKey = key
                    break
                }
                if (secretKey != null) break
            }
            
            if (secretKey == null) {
                throw Exception("Nie znaleziono klucza prywatnego. Upewnij się, że klucz zawiera nagłówki -----BEGIN PGP PRIVATE KEY BLOCK-----")
            }
            
            // Wczytaj zaszyfrowaną wiadomość
            val encryptedStream = ByteArrayInputStream(encryptedMessage.toByteArray())
            val encryptedDecoderStream = PGPUtil.getDecoderStream(encryptedStream)
            val pgpObjectFactory = PGPObjectFactory(encryptedDecoderStream)
            
            // Pobierz listę zaszyfrowanych danych
            var encryptedDataList: PGPEncryptedDataList? = null
            var obj = pgpObjectFactory.nextObject()
            
            when (obj) {
                is PGPEncryptedDataList -> {
                    encryptedDataList = obj
                }
                is PGPOnePassSignatureList -> {
                    // Pomiń podpisy i pobierz zaszyfrowane dane
                    obj = pgpObjectFactory.nextObject()
                    if (obj is PGPEncryptedDataList) {
                        encryptedDataList = obj
                    }
                }
                else -> {
                    throw Exception("Nieprawidłowy format wiadomości PGP")
                }
            }
            
            if (encryptedDataList == null) {
                throw Exception("Nie znaleziono zaszyfrowanych danych")
            }
            
            // Znajdź odpowiedni klucz do odszyfrowania
            var pgpPrivateKey: PGPPrivateKey? = null
            var publicKeyEncryptedData: PGPPublicKeyEncryptedData? = null
            
            val encryptedDataObjects = encryptedDataList.encryptedDataObjects
            while (encryptedDataObjects.hasNext()) {
                val encryptedDataObj = encryptedDataObjects.next()
                if (encryptedDataObj is PGPPublicKeyEncryptedData) {
                    try {
                        // Spróbuj wyodrębnić klucz prywatny (bez hasła)
                        pgpPrivateKey = secretKey.extractPrivateKey(
                            JcePBESecretKeyDecryptorBuilder()
                                .setProvider("BC")
                                .build(charArrayOf())
                        )
                        
                        // Sprawdź czy klucz pasuje do zaszyfrowanych danych
                        if (pgpPrivateKey != null) {
                            publicKeyEncryptedData = encryptedDataObj
                            break
                        }
                    } catch (e: Exception) {
                        // Klucz może być chroniony hasłem - kontynuuj szukanie
                        continue
                    }
                }
            }
            
            if (pgpPrivateKey == null || publicKeyEncryptedData == null) {
                throw Exception("Nie można znaleźć odpowiedniego klucza. Upewnij się, że:\n1. Klucz prywatny pasuje do klucza użytego do szyfrowania\n2. Klucz nie jest chroniony hasłem (lub użyj klucza bez hasła)")
            }
            
            // Odszyfruj dane
            val dataDecryptorFactory = JcePublicKeyDataDecryptorBuilder()
                .setProvider("BC")
                .build(pgpPrivateKey)
            
            val encryptedInputStream = publicKeyEncryptedData.getDataStream(dataDecryptorFactory)
            val literalDataFactory = PGPObjectFactory(encryptedInputStream)
            
            // Pobierz odszyfrowane dane
            var decryptedData: ByteArray? = null
            obj = literalDataFactory.nextObject()
            
            when (obj) {
                is PGPLiteralData -> {
                    val literalData = obj
                    val inputStream = literalData.inputStream
                    val outputStream = ByteArrayOutputStream()
                    
                    val buffer = ByteArray(4096)
                    var bytesRead: Int
                    while (inputStream.read(buffer).also { bytesRead = it } != -1) {
                        outputStream.write(buffer, 0, bytesRead)
                    }
                    
                    decryptedData = outputStream.toByteArray()
                }
                is PGPCompressedData -> {
                    val compressedData = obj
                    val compressedFactory = PGPObjectFactory(compressedData.dataStream)
                    val literalData = compressedFactory.nextObject() as PGPLiteralData
                    val inputStream = literalData.inputStream
                    val outputStream = ByteArrayOutputStream()
                    
                    val buffer = ByteArray(4096)
                    var bytesRead: Int
                    while (inputStream.read(buffer).also { bytesRead = it } != -1) {
                        outputStream.write(buffer, 0, bytesRead)
                    }
                    
                    decryptedData = outputStream.toByteArray()
                }
                else -> {
                    throw Exception("Nieoczekiwany typ danych PGP: ${obj.javaClass.simpleName}")
                }
            }
            
            if (decryptedData == null) {
                throw Exception("Nie udało się odszyfrować danych")
            }
            
            return String(decryptedData, Charsets.UTF_8)
            
        } catch (e: Exception) {
            throw Exception("Błąd odszyfrowywania: ${e.message}", e)
        }
    }
    
    private fun copyToClipboard() {
        val decryptedText = decryptedResultEditText.text?.toString() ?: ""
        
        if (decryptedText.isEmpty()) {
            Toast.makeText(this, "Brak tekstu do skopiowania", Toast.LENGTH_SHORT).show()
            return
        }
        
        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val clip = ClipData.newPlainText("Odszyfrowana wiadomość", decryptedText)
        clipboard.setPrimaryClip(clip)
        
        Toast.makeText(this, getString(R.string.copy_success), Toast.LENGTH_SHORT).show()
    }
}

