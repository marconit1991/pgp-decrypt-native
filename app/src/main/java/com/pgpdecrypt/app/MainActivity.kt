package com.pgpdecrypt.app

import android.app.AlertDialog
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.util.Log
import android.view.LayoutInflater
import android.view.View
import android.widget.EditText
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import com.google.android.material.button.MaterialButton
import com.google.android.material.textfield.TextInputEditText
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openpgp.*
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider
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
    
    private var pendingDecryption: Pair<String, String>? = null // encryptedMessage, privateKeyText
    
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
        
        // Sprawdź czy klucz wymaga hasła
        executorService.execute {
            try {
                val requiresPassword = checkIfKeyRequiresPassword(privateKeyText)
                runOnUiThread {
                    if (requiresPassword) {
                        // Pokaż dialog do wprowadzenia hasła
                        showPasswordDialog(encryptedMessage, privateKeyText)
                    } else {
                        // Klucz nie wymaga hasła, odszyfruj bezpośrednio
                        performDecryption(encryptedMessage, privateKeyText, "")
                    }
                }
            } catch (e: Exception) {
                Log.e("MainActivity", "Error checking if key requires password", e)
                runOnUiThread {
                    // W razie błędu sprawdzania, spróbuj bez hasła
                    performDecryption(encryptedMessage, privateKeyText, "")
                }
            }
        }
    }
    
    private fun checkIfKeyRequiresPassword(privateKeyText: String): Boolean {
        try {
            val fingerprintCalculator = BcKeyFingerprintCalculator()
            val privateKeyStream = ByteArrayInputStream(privateKeyText.toByteArray(Charsets.UTF_8))
            val decoderStream = PGPUtil.getDecoderStream(privateKeyStream)
            val secretKeyRingCollection = PGPSecretKeyRingCollection(decoderStream, fingerprintCalculator)
            
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
                return false
            }
            
            // Spróbuj wyodrębnić klucz bez hasła
            try {
                val digestCalculatorProvider = BcPGPDigestCalculatorProvider()
                secretKey.extractPrivateKey(
                    BcPBESecretKeyDecryptorBuilder(digestCalculatorProvider)
                        .build(charArrayOf())
                )
                return false // Klucz nie wymaga hasła
            } catch (e: Exception) {
                // Jeśli nie udało się bez hasła, klucz wymaga hasła
                return true
            }
        } catch (e: Exception) {
            Log.e("MainActivity", "Error checking password requirement", e)
            return false
        }
    }
    
    private fun showPasswordDialog(encryptedMessage: String, privateKeyText: String) {
        val passwordInput = EditText(this).apply {
            hint = getString(R.string.password_dialog_hint)
            inputType = android.text.InputType.TYPE_CLASS_TEXT or android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD
            setPadding(50, 30, 50, 30)
            setTextColor(ContextCompat.getColor(this@MainActivity, android.R.color.white))
            setHintTextColor(ContextCompat.getColor(this@MainActivity, android.R.color.darker_gray))
        }
        
        val dialog = AlertDialog.Builder(this, android.R.style.Theme_Material_Dialog)
            .setTitle(getString(R.string.password_dialog_title))
            .setMessage(getString(R.string.password_dialog_message))
            .setView(passwordInput)
            .setPositiveButton("Odszyfruj") { _, _ ->
                val password = passwordInput.text?.toString() ?: ""
                performDecryption(encryptedMessage, privateKeyText, password)
            }
            .setNegativeButton("Anuluj") { dialog, _ ->
                decryptButton.isEnabled = true
                decryptButton.text = getString(R.string.decrypt_button)
                dialog.dismiss()
            }
            .create()
        
        dialog.setOnShowListener {
            // Ustaw kolory przycisków
            dialog.getButton(AlertDialog.BUTTON_POSITIVE)?.setTextColor(ContextCompat.getColor(this@MainActivity, android.R.color.white))
            dialog.getButton(AlertDialog.BUTTON_POSITIVE)?.setBackgroundColor(ContextCompat.getColor(this@MainActivity, R.color.color_primary))
            dialog.getButton(AlertDialog.BUTTON_NEGATIVE)?.setTextColor(ContextCompat.getColor(this@MainActivity, android.R.color.white))
        }
        
        dialog.show()
        
        // Ustaw tło dialogu
        dialog.window?.setBackgroundDrawableResource(R.color.color_surface)
    }
    
    private fun performDecryption(encryptedMessage: String, privateKeyText: String, password: String) {
        // Wyłącz przycisk podczas odszyfrowywania
        decryptButton.isEnabled = false
        decryptButton.text = getString(R.string.decrypting)
        
        // Uruchom w tle używając ExecutorService
        executorService.execute {
            try {
                Log.d("MainActivity", "Starting decryption... (password provided: ${password.isNotEmpty()})")
                val decrypted = decryptPGP(encryptedMessage, privateKeyText, password)
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
    
    private fun decryptPGP(encryptedMessage: String, privateKeyText: String, password: String = ""): String {
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
            
            // Wczytaj zaszyfrowaną wiadomość PRZED wyodrębnieniem klucza
            // Musimy najpierw znaleźć KeyID z wiadomości, żeby dopasować odpowiedni klucz
            Log.d("MainActivity", "Loading encrypted message... (length: ${encryptedMessage.length})")
            val encryptedStream = ByteArrayInputStream(encryptedMessage.toByteArray(Charsets.UTF_8))
            val encryptedDecoderStream = PGPUtil.getDecoderStream(encryptedStream)
            val pgpObjectFactory = PGPObjectFactory(encryptedDecoderStream, fingerprintCalculator)
            Log.d("MainActivity", "Encrypted message loaded")
            
            // Pobierz listę zaszyfrowanych danych
            var encryptedDataList: PGPEncryptedDataList? = null
            var obj: Any? = pgpObjectFactory.nextObject()
            
            // Przeszukaj wszystkie obiekty aż znajdziemy PGPEncryptedDataList
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
                throw Exception("Nie znaleziono zaszyfrowanych danych. Sprawdź format wiadomości PGP.")
            }
            
            // Znajdź odpowiedni zaszyfrowany obiekt i jego KeyID
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
            Log.d("MainActivity", "Required KeyID: $requiredKeyID")
            
            // Znajdź klucz prywatny pasujący do KeyID z wiadomości
            var secretKey: PGPSecretKey? = null
            val keyRings = secretKeyRingCollection.keyRings
            while (keyRings.hasNext()) {
                val keyRing = keyRings.next() as PGPSecretKeyRing
                val keys = keyRing.secretKeys
                while (keys.hasNext()) {
                    val key = keys.next() as PGPSecretKey
                    val keyID = key.keyID
                    Log.d("MainActivity", "Checking key with KeyID: $keyID")
                    if (keyID == requiredKeyID) {
                        secretKey = key
                        Log.d("MainActivity", "Found matching key!")
                        break
                    }
                }
                if (secretKey != null) break
            }
            
            // Jeśli nie znaleziono pasującego KeyID, użyj pierwszego dostępnego klucza
            if (secretKey == null) {
                Log.w("MainActivity", "No matching KeyID found, using first available key")
                val keyRings2 = secretKeyRingCollection.keyRings
                while (keyRings2.hasNext()) {
                    val keyRing = keyRings2.next() as PGPSecretKeyRing
                    val keys = keyRing.secretKeys
                    while (keys.hasNext()) {
                        val key = keys.next() as PGPSecretKey
                        secretKey = key
                        Log.d("MainActivity", "Using first available key with KeyID: ${key.keyID}")
                        break
                    }
                    if (secretKey != null) break
                }
            }
            
            if (secretKey == null) {
                throw Exception("Nie znaleziono klucza prywatnego. Upewnij się, że klucz zawiera nagłówki -----BEGIN PGP PRIVATE KEY BLOCK-----")
            }
            
            // Wyodrębnij klucz prywatny (z hasłem lub bez)
            Log.d("MainActivity", "Extracting private key... (password provided: ${password.isNotEmpty()})")
            val digestCalculatorProvider = BcPGPDigestCalculatorProvider()
            val pgpPrivateKey = try {
                secretKey.extractPrivateKey(
                    BcPBESecretKeyDecryptorBuilder(digestCalculatorProvider)
                        .build(password.toCharArray())
                )
            } catch (e: Exception) {
                Log.e("MainActivity", "Error extracting private key", e)
                if (password.isEmpty()) {
                    throw Exception("Błąd wyodrębniania klucza prywatnego. Klucz może wymagać hasła. ${e.message}")
                } else {
                    throw Exception("Błąd wyodrębniania klucza prywatnego. Sprawdź czy hasło jest poprawne. ${e.message}")
                }
            }
            Log.d("MainActivity", "Private key extracted successfully")
            
            // Odszyfruj dane używając dopasowanego klucza
            Log.d("MainActivity", "Decrypting data with KeyID: $requiredKeyID")
            val dataDecryptorFactory = BcPublicKeyDataDecryptorFactory(pgpPrivateKey)
            
            var encryptedInputStream: InputStream? = null
            try {
                encryptedInputStream = publicKeyEncryptedData.getDataStream(dataDecryptorFactory)
                Log.d("MainActivity", "Data stream obtained, reading decrypted data...")
                
                val literalDataFactory = PGPObjectFactory(encryptedInputStream, fingerprintCalculator)
                
                // Pobierz odszyfrowane dane - obsługuj różne formaty
                var decryptedObj: Any? = literalDataFactory.nextObject()
                var decryptedData: ByteArray? = null
                
                while (decryptedObj != null && decryptedData == null) {
                    when (decryptedObj) {
                        is PGPLiteralData -> {
                            decryptedData = readLiteralData(decryptedObj)
                            break
                        }
                        is PGPCompressedData -> {
                            val compressedData = decryptedObj
                            val compressedFactory = PGPObjectFactory(compressedData.dataStream, fingerprintCalculator)
                            decryptedObj = compressedFactory.nextObject()
                            continue
                        }
                        else -> {
                            // Spróbuj następny obiekt
                            decryptedObj = try {
                                literalDataFactory.nextObject()
                            } catch (e: Exception) {
                                null
                            }
                        }
                    }
                }
                
                if (decryptedData == null) {
                    throw Exception("Nie znaleziono danych do odszyfrowania w wiadomości PGP")
                }
                
                return String(decryptedData, Charsets.UTF_8)
            } catch (e: Exception) {
                Log.e("MainActivity", "Error decrypting data stream", e)
                throw Exception("Błąd odszyfrowywania danych sesji. ${e.message}")
            } finally {
                try {
                    encryptedInputStream?.close()
                } catch (e: Exception) {
                    Log.w("MainActivity", "Error closing stream", e)
                }
            }
            
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
        val clip = ClipData.newPlainText("Token", decryptedText)
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
