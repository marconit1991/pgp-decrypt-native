package com.pgpdecrypt.app

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.util.Log
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.button.MaterialButton
import com.google.android.material.textfield.TextInputEditText
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openpgp.*
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.security.Security
import java.util.concurrent.Executors

class MainActivity : AppCompatActivity() {
    
    private lateinit var encryptedMessageEditText: TextInputEditText
    private lateinit var privateKeyEditText: TextInputEditText
    private lateinit var decryptedResultEditText: TextInputEditText
    private lateinit var decryptButton: MaterialButton
    private lateinit var copyButton: MaterialButton
    private lateinit var loadKeyFromFileButton: MaterialButton
    
    private val executorService = Executors.newSingleThreadExecutor()
    
    private val filePickerLauncher = registerForActivityResult(ActivityResultContracts.GetContent()) { uri: Uri? ->
        uri?.let {
            loadKeyFromFile(it)
        }
    }
    
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
            loadKeyFromFileButton = findViewById(R.id.loadKeyFromFileButton)
            
            // Przycisk odszyfrowywania
            decryptButton.setOnClickListener {
                decryptPGPMessage()
            }
            
            // Przycisk kopiowania
            copyButton.setOnClickListener {
                copyToClipboard()
            }
            
            // Przycisk wczytania klucza z pliku
            loadKeyFromFileButton.setOnClickListener {
                openFilePicker()
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
        
        // Uruchom w tle używając ExecutorService
        executorService.execute {
            try {
                Log.d("MainActivity", "Starting decryption...")
                val decrypted = decryptPGP(encryptedMessage, privateKeyText)
                Log.d("MainActivity", "Decryption successful, length: ${decrypted.length}")
                
                runOnUiThread {
                    try {
                        if (!isFinishing && !isDestroyed) {
                            decryptedResultEditText.setText(decrypted)
                            copyButton.isEnabled = true
                            decryptButton.isEnabled = true
                            decryptButton.text = getString(R.string.decrypt_button)
                            Toast.makeText(this, "✅ Odszyfrowano pomyślnie!", Toast.LENGTH_SHORT).show()
                        }
                    } catch (e: Exception) {
                        Log.e("MainActivity", "Error updating UI", e)
                        e.printStackTrace()
                        if (!isFinishing && !isDestroyed) {
                            Toast.makeText(this, "Błąd aktualizacji UI: ${e.message}", Toast.LENGTH_LONG).show()
                        }
                    }
                }
            } catch (e: Throwable) {
                Log.e("MainActivity", "Decryption error", e)
                e.printStackTrace()
                val errorMessage = e.message ?: "Nieznany błąd"
                val errorDetails = e.stackTraceToString()
                
                runOnUiThread {
                    try {
                        if (!isFinishing && !isDestroyed) {
                            decryptedResultEditText.setText("❌ Błąd: $errorMessage\n\nSzczegóły:\n$errorDetails")
                            decryptButton.isEnabled = true
                            decryptButton.text = getString(R.string.decrypt_button)
                            Toast.makeText(this, "${getString(R.string.error_decrypt)}: $errorMessage", Toast.LENGTH_LONG).show()
                        }
                    } catch (uiError: Exception) {
                        Log.e("MainActivity", "Error showing error message", uiError)
                        uiError.printStackTrace()
                    }
                }
            }
        }
    }
    
    private fun decryptPGP(encryptedMessage: String, privateKeyText: String): String {
        try {
            Log.d("MainActivity", "Initializing BouncyCastle...")
            
            // Upewnij się że BouncyCastle jest dostępny
            try {
                if (Security.getProvider("BC") == null) {
                    Security.addProvider(BouncyCastleProvider())
                }
                Log.d("MainActivity", "BouncyCastle provider ready")
            } catch (e: Exception) {
                Log.w("MainActivity", "BouncyCastle provider issue", e)
                // Kontynuuj - może już jest dodany
            }
            
            val fingerprintCalculator = BcKeyFingerprintCalculator()
            
            // Wczytaj klucz prywatny
            Log.d("MainActivity", "Loading private key... (length: ${privateKeyText.length})")
            
            if (!privateKeyText.contains("-----BEGIN PGP")) {
                throw Exception("Klucz prywatny nie zawiera nagłówka PGP. Sprawdź format klucza.")
            }
            
            val privateKeyStream = ByteArrayInputStream(privateKeyText.toByteArray(Charsets.UTF_8))
            val decoderStream = PGPUtil.getDecoderStream(privateKeyStream)
            val secretKeyRingCollection = PGPSecretKeyRingCollection(decoderStream, fingerprintCalculator)
            Log.d("MainActivity", "Private key loaded successfully")
            
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
            // Używamy BcPBESecretKeyDecryptorBuilder zamiast JcePBESecretKeyDecryptorBuilder
            // bo JCE może mieć problemy z SHA-1 na Androidzie
            Log.d("MainActivity", "Extracting private key...")
            val pgpPrivateKey = try {
                secretKey.extractPrivateKey(
                    BcPBESecretKeyDecryptorBuilder()
                        .build(charArrayOf())
                )
            } catch (e: Exception) {
                Log.e("MainActivity", "Error extracting private key", e)
                throw Exception("Błąd wyodrębniania klucza prywatnego. Może klucz wymaga hasła? ${e.message}")
            }
            Log.d("MainActivity", "Private key extracted")
            
            // Wczytaj zaszyfrowaną wiadomość
            Log.d("MainActivity", "Loading encrypted message... (length: ${encryptedMessage.length})")
            val encryptedStream = ByteArrayInputStream(encryptedMessage.toByteArray(Charsets.UTF_8))
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
            Log.d("MainActivity", "Decrypting data...")
            val dataDecryptorFactory = BcPublicKeyDataDecryptorFactory(pgpPrivateKey)
            val encryptedInputStream: InputStream = try {
                publicKeyEncryptedData.getDataStream(dataDecryptorFactory)
            } catch (e: Exception) {
                Log.e("MainActivity", "Error getting data stream", e)
                throw Exception("Błąd odszyfrowywania danych. Sprawdź czy klucz pasuje do wiadomości. ${e.message}")
            }
            val literalDataFactory = PGPObjectFactory(encryptedInputStream, fingerprintCalculator)
            Log.d("MainActivity", "Data stream obtained")
            
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
            
            val result = String(decryptedData, Charsets.UTF_8)
            Log.d("MainActivity", "Decryption complete, result length: ${result.length}")
            return result
            
        } catch (e: Exception) {
            Log.e("MainActivity", "Decryption failed", e)
            e.printStackTrace()
            throw Exception("Błąd odszyfrowywania: ${e.message}", e)
        } catch (e: Throwable) {
            Log.e("MainActivity", "Decryption failed with Throwable", e)
            e.printStackTrace()
            throw Exception("Krytyczny błąd odszyfrowywania: ${e.message}", e)
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
    
    private fun openFilePicker() {
        try {
            val intent = Intent(Intent.ACTION_GET_CONTENT).apply {
                type = "*/*"
                addCategory(Intent.CATEGORY_OPENABLE)
                putExtra(Intent.EXTRA_MIME_TYPES, arrayOf("text/plain", "text/*", "*/*"))
            }
            filePickerLauncher.launch("*/*")
        } catch (e: Exception) {
            Log.e("MainActivity", "Error opening file picker", e)
            Toast.makeText(this, "Błąd otwierania wyboru pliku: ${e.message}", Toast.LENGTH_LONG).show()
        }
    }
    
    private fun loadKeyFromFile(uri: Uri) {
        try {
            contentResolver.openInputStream(uri)?.use { inputStream ->
                val content = inputStream.bufferedReader().use { it.readText() }
                
                // Sprawdź czy to wygląda na klucz PGP
                if (content.contains("-----BEGIN PGP") || content.contains("PRIVATE KEY")) {
                    privateKeyEditText.setText(content.trim())
                    Toast.makeText(this, getString(R.string.file_loaded), Toast.LENGTH_SHORT).show()
                } else {
                    // Spróbuj wczytać mimo wszystko - może być w innym formacie
                    privateKeyEditText.setText(content.trim())
                    Toast.makeText(this, "Plik wczytany (sprawdź czy to klucz PGP)", Toast.LENGTH_SHORT).show()
                }
            } ?: run {
                Toast.makeText(this, "Nie można odczytać pliku", Toast.LENGTH_SHORT).show()
            }
        } catch (e: Exception) {
            Log.e("MainActivity", "Error reading file", e)
            Toast.makeText(this, "${getString(R.string.error_reading_file)}: ${e.message}", Toast.LENGTH_LONG).show()
        }
    }
    
    override fun onDestroy() {
        super.onDestroy()
        try {
            executorService.shutdown()
        } catch (e: Exception) {
            Log.w("MainActivity", "Error shutting down executor", e)
        }
    }
}
