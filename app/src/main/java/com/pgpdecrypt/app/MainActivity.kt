package com.pgpdecrypt.app

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Bundle
import android.util.Log
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.button.MaterialButton
import com.google.android.material.textfield.TextInputEditText
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openpgp.*
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.security.Security

class MainActivity : AppCompatActivity() {
    
    private lateinit var encryptedMessageEditText: TextInputEditText
    private lateinit var privateKeyEditText: TextInputEditText
    private lateinit var decryptedResultEditText: TextInputEditText
    private lateinit var decryptButton: MaterialButton
    private lateinit var copyButton: MaterialButton
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        try {
            setContentView(R.layout.activity_main)
        } catch (e: Exception) {
            Log.e("MainActivity", "Error setting content view", e)
            Toast.makeText(this, "Błąd ładowania interfejsu: ${e.message}", Toast.LENGTH_LONG).show()
            finish()
            return
        }
        
        try {
            // Dodaj BouncyCastle provider
            if (Security.getProvider("BC") == null) {
                Security.addProvider(BouncyCastleProvider())
            }
        } catch (e: Exception) {
            Log.w("MainActivity", "BouncyCastle provider already added or error", e)
        }
        
        try {
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
        } catch (e: Exception) {
            Log.e("MainActivity", "Error initializing views", e)
            Toast.makeText(this, "Błąd inicjalizacji: ${e.message}", Toast.LENGTH_LONG).show()
            finish()
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
                Log.d("MainActivity", "Starting decryption...")
                val decrypted = decryptPGP(encryptedMessage, privateKeyText)
                Log.d("MainActivity", "Decryption successful")
                
                runOnUiThread {
                    try {
                        decryptedResultEditText.setText(decrypted)
                        copyButton.isEnabled = true
                        decryptButton.isEnabled = true
                        decryptButton.text = getString(R.string.decrypt_button)
                        Toast.makeText(this, "✅ Odszyfrowano pomyślnie!", Toast.LENGTH_SHORT).show()
                    } catch (e: Exception) {
                        Log.e("MainActivity", "Error updating UI", e)
                        Toast.makeText(this, "Błąd aktualizacji UI: ${e.message}", Toast.LENGTH_LONG).show()
                    }
                }
            } catch (e: Exception) {
                Log.e("MainActivity", "Decryption error", e)
                e.printStackTrace()
                runOnUiThread {
                    try {
                        decryptedResultEditText.setText("❌ Błąd: ${e.message}\n\n${e.stackTraceToString()}")
                        decryptButton.isEnabled = true
                        decryptButton.text = getString(R.string.decrypt_button)
                        Toast.makeText(this, "${getString(R.string.error_decrypt)}: ${e.message}", Toast.LENGTH_LONG).show()
                    } catch (uiError: Exception) {
                        Log.e("MainActivity", "Error showing error message", uiError)
                    }
                }
            }
        }.start()
    }
    
    private fun decryptPGP(encryptedMessage: String, privateKeyText: String): String {
        try {
            Log.d("MainActivity", "Initializing BouncyCastle...")
            val fingerprintCalculator = BcKeyFingerprintCalculator()
            
            // Upewnij się że BouncyCastle jest dostępny
            if (Security.getProvider("BC") == null) {
                Security.addProvider(BouncyCastleProvider())
            }
            // Wczytaj klucz prywatny
            Log.d("MainActivity", "Loading private key...")
            val privateKeyStream = ByteArrayInputStream(privateKeyText.toByteArray())
            val decoderStream = PGPUtil.getDecoderStream(privateKeyStream)
            val secretKeyRingCollection = PGPSecretKeyRingCollection(decoderStream, fingerprintCalculator)
            Log.d("MainActivity", "Private key loaded")
            
            // Znajdź pierwszy klucz prywatny
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
            
            // Wyodrębnij klucz prywatny (bez hasła)
            val pgpPrivateKey = secretKey.extractPrivateKey(
                JcePBESecretKeyDecryptorBuilder()
                    .setProvider("BC")
                    .build(charArrayOf())
            )
            
            // Wczytaj zaszyfrowaną wiadomość
            Log.d("MainActivity", "Loading encrypted message...")
            val encryptedStream = ByteArrayInputStream(encryptedMessage.toByteArray())
            val encryptedDecoderStream = PGPUtil.getDecoderStream(encryptedStream)
            val pgpObjectFactory = PGPObjectFactory(encryptedDecoderStream, fingerprintCalculator)
            Log.d("MainActivity", "Encrypted message loaded")
            
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
            
            // Znajdź odpowiedni zaszyfrowany obiekt
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
            
            // Odszyfruj dane
            val dataDecryptorFactory = BcPublicKeyDataDecryptorFactory(pgpPrivateKey)
            val encryptedInputStream: InputStream = publicKeyEncryptedData.getDataStream(dataDecryptorFactory)
            val literalDataFactory = PGPObjectFactory(encryptedInputStream, fingerprintCalculator)
            
            // Pobierz odszyfrowane dane
            obj = literalDataFactory.nextObject()
            
            val decryptedData = when (obj) {
                is PGPLiteralData -> {
                    readLiteralData(obj)
                }
                is PGPCompressedData -> {
                    val compressedData = obj
                    val compressedFactory = PGPObjectFactory(compressedData.dataStream, fingerprintCalculator)
                    val literalData = compressedFactory.nextObject() as PGPLiteralData
                    readLiteralData(literalData)
                }
                else -> {
                    throw Exception("Nieoczekiwany typ danych PGP: ${obj.javaClass.simpleName}")
                }
            }
            
            return String(decryptedData, Charsets.UTF_8)
            
        } catch (e: Exception) {
            throw Exception("Błąd odszyfrowywania: ${e.message}", e)
        }
    }
    
    private fun readLiteralData(literalData: PGPLiteralData): ByteArray {
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
