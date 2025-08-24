package com.qrypteye.app.ui

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Bundle
import android.view.View
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.camera.core.*
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import com.google.android.material.snackbar.Snackbar
import com.google.zxing.BinaryBitmap
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeReader
import com.qrypteye.app.R
import com.qrypteye.app.crypto.CryptoManager
import com.qrypteye.app.data.Contact
import com.qrypteye.app.data.DataManager
import com.qrypteye.app.data.Message
import com.qrypteye.app.databinding.ActivityScanQrBinding
import com.qrypteye.app.qr.QRCodeManager
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.util.*
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import com.qrypteye.app.data.ContactValidator

class ScanQRActivity : AppCompatActivity() {
    
    private lateinit var binding: ActivityScanQrBinding
    private lateinit var cameraExecutor: ExecutorService
    private lateinit var cryptoManager: CryptoManager
    private lateinit var qrCodeManager: QRCodeManager
    private lateinit var dataManager: DataManager
    
    private var imageCapture: ImageCapture? = null
    private var camera: Camera? = null
    private var userPrivateKey: PrivateKey? = null
    private var isImportMode: Boolean = false
    private var isProcessingQR: Boolean = false
    private var isMessageProcessed: Boolean = false // Flag to prevent multiple processing
    
    companion object {
        private const val CAMERA_PERMISSION_REQUEST = 100
        private val secureRandom = SecureRandom()
        
        private fun generateSecureId(): String {
            val bytes = ByteArray(16)
            secureRandom.nextBytes(bytes)
            return android.util.Base64.encodeToString(bytes, android.util.Base64.URL_SAFE or android.util.Base64.NO_PADDING)
        }
    }
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityScanQrBinding.inflate(layoutInflater)
        setContentView(binding.root)
        
        cameraExecutor = Executors.newSingleThreadExecutor()
        cryptoManager = CryptoManager()
        qrCodeManager = QRCodeManager()
        dataManager = DataManager(this)
        
        // Check if we're in import mode
        isImportMode = intent.getBooleanExtra("import_mode", false)
        
        setSupportActionBar(binding.toolbar)
        supportActionBar?.setDisplayHomeAsUpEnabled(true)
        
        // Update title for import mode
        if (isImportMode) {
            supportActionBar?.title = "Import Public Key"
        }
        
        setupUI()
        loadUserKeyPair()
        
        if (allPermissionsGranted()) {
            startCamera()
        } else {
            ActivityCompat.requestPermissions(
                this, arrayOf(Manifest.permission.CAMERA), CAMERA_PERMISSION_REQUEST
            )
        }
    }
    
    private fun setupUI() {
        binding.toolbar.setNavigationOnClickListener {
            finish()
        }
        
        binding.copyMessageButton.setOnClickListener {
            copyDecryptedMessage()
        }
        
        binding.closeMessageButton.setOnClickListener {
            hideDecryptedMessage()
        }
        
        // Update scan status for import mode
        if (isImportMode) {
            binding.scanStatus.text = "Ready to scan public key QR code"
        }
    }
    
    private fun loadUserKeyPair() {
        // Load user's key pair from Android Keystore
        android.util.Log.d("ScanQRActivity", "Loading user key pair from Android Keystore")
        val keyPair = dataManager.loadKeyPair()
        if (keyPair != null) {
            try {
                android.util.Log.d("ScanQRActivity", "Key pair loaded successfully")
                android.util.Log.d("ScanQRActivity", "Public key algorithm: ${keyPair.public.algorithm}")
                android.util.Log.d("ScanQRActivity", "Private key algorithm: ${keyPair.private.algorithm}")
                
                // SECURITY: Private key is accessed directly from KeyPair object
                // No serialization or string conversion
                userPrivateKey = keyPair.private
                android.util.Log.d("ScanQRActivity", "User private key set successfully")
            } catch (e: Exception) {
                android.util.Log.e("ScanQRActivity", "Failed to load user key pair: ${e.message}", e)
                showError("Failed to load user key pair: ${e.message}")
            }
        } else {
            android.util.Log.e("ScanQRActivity", "No key pair found in Android Keystore")
            showError("No key pair found. Please generate keys first.")
        }
    }
    
    private fun startCamera() {
        val cameraProviderFuture = ProcessCameraProvider.getInstance(this)
        
        cameraProviderFuture.addListener({
            val cameraProvider: ProcessCameraProvider = cameraProviderFuture.get()
            
            val preview = Preview.Builder()
                .build()
                .also {
                    it.setSurfaceProvider(binding.cameraPreview.surfaceProvider)
                }
            
            imageCapture = ImageCapture.Builder()
                .setCaptureMode(ImageCapture.CAPTURE_MODE_MINIMIZE_LATENCY)
                .build()
            
            val imageAnalyzer = ImageAnalysis.Builder()
                .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                .build()
                .also {
                    it.setAnalyzer(cameraExecutor, QRCodeAnalyzer())
                }
            
            try {
                cameraProvider.unbindAll()
                
                camera = cameraProvider.bindToLifecycle(
                    this,
                    CameraSelector.DEFAULT_BACK_CAMERA,
                    preview,
                    imageCapture,
                    imageAnalyzer
                )
                
            } catch (exc: Exception) {
                showError("Camera binding failed: ${exc.message}")
            }
            
        }, ContextCompat.getMainExecutor(this))
    }
    
    private fun stopCamera() {
        try {
            val cameraProvider = ProcessCameraProvider.getInstance(this).get()
            cameraProvider.unbindAll()
        } catch (exc: Exception) {
            // Ignore errors when stopping camera
        }
    }
    
    private fun allPermissionsGranted() = ContextCompat.checkSelfPermission(
        baseContext, Manifest.permission.CAMERA
    ) == PackageManager.PERMISSION_GRANTED
    
    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<String>,
        grantResults: IntArray
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == CAMERA_PERMISSION_REQUEST) {
            if (allPermissionsGranted()) {
                startCamera()
            } else {
                showError("Camera permission is required to scan QR codes")
                finish()
            }
        }
    }
    
    private fun processQRCode(qrContent: String) {
        if (isProcessingQR || isMessageProcessed) {
            return // Already processing a QR code or message already processed
        }
        
        isProcessingQR = true
        binding.scanStatus.text = getString(R.string.qr_code_detected)
        
        when (qrCodeManager.getQRCodeType(qrContent)) {
            QRCodeManager.QRCodeType.SIGNED_ENCRYPTED_MESSAGE -> {
                if (isImportMode) {
                    showError("This QR code contains a message, not a public key")
                    isProcessingQR = false
                } else {
                    processSignedEncryptedMessage(qrContent)
                }
            }
            QRCodeManager.QRCodeType.PUBLIC_KEY -> {
                if (isImportMode) {
                    importPublicKey(qrContent)
                } else {
                    showError("This QR code contains a public key, not a message")
                    isProcessingQR = false
                }
            }
            QRCodeManager.QRCodeType.UNKNOWN -> {
                showError("Invalid QR code format")
                isProcessingQR = false
            }
        }
    }
    
    private fun processSignedEncryptedMessage(qrContent: String) {
        try {
            android.util.Log.d("ScanQRActivity", "Processing signed encrypted message, content length: ${qrContent.length}")
            binding.scanStatus.text = getString(R.string.verifying_authenticity)
            
            val signedMessage = qrCodeManager.parseSignedEncryptedMessage(qrContent)
            android.util.Log.d("ScanQRActivity", "parseSignedEncryptedMessage result: ${signedMessage != null}")
            
            if (signedMessage != null) {
                android.util.Log.d("ScanQRActivity", "Signed message parsed successfully")
                
                // Get sender's public key from contacts
                val senderPublicKey = getSenderPublicKey(signedMessage)
                val privateKey = userPrivateKey
                
                android.util.Log.d("ScanQRActivity", "Sender public key found: ${senderPublicKey != null}")
                android.util.Log.d("ScanQRActivity", "User private key available: ${privateKey != null}")
                
                if (senderPublicKey == null) {
                    android.util.Log.e("ScanQRActivity", "Sender public key not found")
                    showError(getString(R.string.sender_key_not_found))
                    return
                }
                
                if (privateKey == null) {
                    android.util.Log.e("ScanQRActivity", "User private key not available")
                    showError("User key pair not available")
                    return
                }
                
                android.util.Log.d("ScanQRActivity", "Starting verifyAndDecryptMessage")
                
                // Verify and decrypt the message
                val result = cryptoManager.verifyAndDecryptMessage(
                    signedMessage, senderPublicKey, privateKey
                )
                
                android.util.Log.d("ScanQRActivity", "verifyAndDecryptMessage result type: ${result::class.simpleName}")
                
                when (result) {
                    is CryptoManager.VerificationResult.Success -> {
                        android.util.Log.d("ScanQRActivity", "Message decryption successful")
                        
                        // Set flag to prevent further processing
                        isMessageProcessed = true
                        
                        // Stop camera immediately to prevent further scanning
                        stopCamera()
                        
                        showAuthenticatedMessage(result.message)
                        
                        // Save message to conversation history
                        saveReceivedMessage(result.message, signedMessage)
                        
                        // Reset processing flag after successful processing
                        isProcessingQR = false
                    }
                    is CryptoManager.VerificationResult.AuthenticationFailed -> {
                        android.util.Log.e("ScanQRActivity", "Authentication failed")
                        showError(getString(R.string.authenticity_failed))
                        isProcessingQR = false
                    }
                    is CryptoManager.VerificationResult.ReplayAttack -> {
                        android.util.Log.e("ScanQRActivity", "Replay attack detected")
                        showError("⚠️ Replay attack detected: This message is too old or from the future")
                        isProcessingQR = false
                    }
                    is CryptoManager.VerificationResult.DecryptionFailed -> {
                        android.util.Log.e("ScanQRActivity", "Decryption failed: ${result.error}")
                        showError("Decryption failed: ${result.error}")
                        isProcessingQR = false
                    }
                }
            } else {
                android.util.Log.e("ScanQRActivity", "Failed to parse signed message")
                showError("Failed to parse signed message")
            }
        } catch (e: Exception) {
            android.util.Log.e("ScanQRActivity", "Exception in processSignedEncryptedMessage: ${e.message}", e)
            showError("Failed to process signed message: ${e.message}")
            isProcessingQR = false
        }
    }
    
    private fun saveReceivedMessage(messageContent: String, signedMessage: CryptoManager.SignedEncryptedMessage) {
        try {
            android.util.Log.d("ScanQRActivity", "Saving received message, content length: ${messageContent.length}")
            
            // Get the sender name from the signed message
            val senderName = signedMessage.encryptedMessage.senderName
            android.util.Log.d("ScanQRActivity", "Message sender: $senderName")
            
            // Verify that the sender contact exists
            val contacts = dataManager.loadContacts()
            val senderContact = contacts.find { it.name == senderName }
            
            if (senderContact != null) {
                android.util.Log.d("ScanQRActivity", "Found sender contact: ${senderContact.name}")
                val userName = dataManager.getUserName()
                android.util.Log.d("ScanQRActivity", "Current user name: $userName")
                
                // Get the sender's public key for verification
                val senderPublicKey = getSenderPublicKey(signedMessage)
                if (senderPublicKey == null) {
                    android.util.Log.e("ScanQRActivity", "Could not get sender public key")
                    showError("⚠️ Could not verify message sender")
                    return
                }
                
                val receivedMessage = Message(
                    id = generateSecureId(),
                    senderName = senderContact.name,
                    recipientName = userName,
                    content = messageContent,
                    timestamp = System.currentTimeMillis(),
                    isOutgoing = false,
                    isRead = false
                )
                
                android.util.Log.d("ScanQRActivity", "Created received message with ID: ${receivedMessage.id}")
                
                // SECURITY: Verify and add message with cryptographic signature verification
                val wasVerified = dataManager.verifyAndAddMessage(receivedMessage, signedMessage, senderPublicKey)
                
                android.util.Log.d("ScanQRActivity", "Message verification result: $wasVerified")
                
                if (!wasVerified) {
                    android.util.Log.e("ScanQRActivity", "Message authenticity verification failed")
                    showError("⚠️ Message authenticity verification failed")
                } else {
                    android.util.Log.d("ScanQRActivity", "Message saved successfully to conversation history")
                    
                    // Stop camera to prevent further scanning
                    stopCamera()
                    
                    // Show success message and close after delay
                    showSuccess("Message received and saved successfully!")
                    binding.root.postDelayed({
                        finish()
                    }, 3000)
                }
                
            } else {
                android.util.Log.e("ScanQRActivity", "Could not find sender contact: $senderName")
                showError("⚠️ Could not identify message sender: $senderName")
                
                // Stop camera to prevent further scanning
                stopCamera()
                
                // Close after delay
                binding.root.postDelayed({
                    finish()
                }, 3000)
            }
        } catch (e: Exception) {
            android.util.Log.e("ScanQRActivity", "Error saving received message: ${e.message}", e)
            showError("Failed to save message: ${e.message}")
            
            // Stop camera to prevent further scanning
            stopCamera()
            
            // Close after delay
            binding.root.postDelayed({
                finish()
            }, 3000)
        }
    }
    
    private fun getSenderPublicKey(signedMessage: CryptoManager.SignedEncryptedMessage): PublicKey? {
        return try {
            android.util.Log.d("ScanQRActivity", "Extracting sender information from signed message")
            
            // Extract sender information from the encrypted message
            val senderName = signedMessage.encryptedMessage.senderName
            val senderPublicKeyHash = signedMessage.encryptedMessage.senderPublicKeyHash
            
            android.util.Log.d("ScanQRActivity", "Message sender: $senderName")
            android.util.Log.d("ScanQRActivity", "Sender public key hash: $senderPublicKeyHash")
            
            // Find the sender contact by name and verify public key hash
            val contacts = dataManager.loadContacts()
            android.util.Log.d("ScanQRActivity", "Found ${contacts.size} contacts to check")
            
            val senderContact = contacts.find { contact ->
                try {
                    val contactPublicKey = cryptoManager.importPublicKey(contact.publicKeyString)
                    val contactPublicKeyHash = java.security.MessageDigest.getInstance("SHA-256")
                        .digest(contactPublicKey.encoded)
                        .let { android.util.Base64.encodeToString(it, android.util.Base64.URL_SAFE or android.util.Base64.NO_WRAP) }
                    
                    val isMatch = contact.name == senderName && contactPublicKeyHash == senderPublicKeyHash
                    android.util.Log.d("ScanQRActivity", "Comparing contact ${contact.name}: ${if (isMatch) "MATCH" else "no match"}")
                    isMatch
                } catch (e: Exception) {
                    android.util.Log.e("ScanQRActivity", "Error comparing public keys for contact ${contact.name}: ${e.message}")
                    false
                }
            }
            
            if (senderContact != null) {
                android.util.Log.d("ScanQRActivity", "Found matching sender contact: ${senderContact.name}")
                val publicKey = cryptoManager.importPublicKey(senderContact.publicKeyString)
                android.util.Log.d("ScanQRActivity", "Successfully imported public key for ${senderContact.name}")
                return publicKey
            } else {
                android.util.Log.e("ScanQRActivity", "No matching contact found for sender: $senderName")
                return null
            }
        } catch (e: Exception) {
            android.util.Log.e("ScanQRActivity", "Error in getSenderPublicKey: ${e.message}", e)
            null
        }
    }
    
    private fun importPublicKey(qrContent: String) {
        try {
            android.util.Log.d("ScanQRActivity", "Starting public key import process")
            android.util.Log.d("ScanQRActivity", "QR content length: ${qrContent.length}")
            
            val publicKeyData = qrCodeManager.parsePublicKeyData(qrContent)
            
            if (publicKeyData != null) {
                android.util.Log.d("ScanQRActivity", "Successfully parsed public key data")
                android.util.Log.d("ScanQRActivity", "Contact name: ${publicKeyData.contactName}")
                android.util.Log.d("ScanQRActivity", "Public key length: ${publicKeyData.publicKey.length}")
                android.util.Log.d("ScanQRActivity", "Timestamp: ${publicKeyData.timestamp}")
                
                // SECURITY: Validate timestamp before processing
                val timestampValidation = com.qrypteye.app.data.ContactValidator.validateTimestamp(
                    publicKeyData.timestamp, "public key"
                )
                if (timestampValidation !is com.qrypteye.app.data.ContactValidator.TimestampValidationResult.Valid) {
                    android.util.Log.w("ScanQRActivity", "Timestamp validation failed: ${timestampValidation.message}")
                    showError("⚠️ ${timestampValidation.message}")
                    isProcessingQR = false
                    return
                }
                
                // SECURITY: Check for replay attacks on public key import
                val currentTime = System.currentTimeMillis()
                val maxAge = 24 * 60 * 60 * 1000L // 24 hours
                val maxFuture = 5 * 60 * 1000L // 5 minutes for clock skew
                
                if (currentTime - publicKeyData.timestamp > maxAge) {
                    android.util.Log.w("ScanQRActivity", "Replay attack detected: Public key QR code is too old")
                    showError("⚠️ Replay attack detected: Public key QR code is too old")
                    isProcessingQR = false
                    return
                }
                
                if (publicKeyData.timestamp - currentTime > maxFuture) {
                    android.util.Log.w("ScanQRActivity", "Invalid timestamp: Public key QR code is from the future")
                    showError("⚠️ Invalid timestamp: Public key QR code is from the future")
                    isProcessingQR = false
                    return
                }
                
                // Create contact from public key data with comprehensive validation
                val contact = try {
                    android.util.Log.d("ScanQRActivity", "Attempting to create contact with original public key")
                    Contact.createContactFromString(
                        name = publicKeyData.contactName,
                        publicKeyString = publicKeyData.publicKey
                    )
                } catch (e: IllegalArgumentException) {
                    android.util.Log.w("ScanQRActivity", "Initial contact creation failed: ${e.message}")
                    android.util.Log.d("ScanQRActivity", "Attempting key repair...")
                    
                    // Attempt to repair the key if initial validation fails
                    val repairResult = com.qrypteye.app.data.ContactValidator.attemptKeyRepair(publicKeyData.publicKey)
                    android.util.Log.d("ScanQRActivity", "Key repair result: ${repairResult.message}")
                    
                    if (repairResult is com.qrypteye.app.data.ContactValidator.RepairResult.Repaired) {
                        try {
                            android.util.Log.d("ScanQRActivity", "Attempting to create contact with repaired key")
                            Contact.createContactFromString(
                                name = publicKeyData.contactName,
                                publicKeyString = repairResult.repairedKey
                            ).also {
                                android.util.Log.d("ScanQRActivity", "Successfully created contact with repaired key")
                                showSuccess("Public key repaired using ${repairResult.encodingUsed} encoding")
                            }
                        } catch (e2: IllegalArgumentException) {
                            android.util.Log.e("ScanQRActivity", "Contact creation with repaired key failed: ${e2.message}")
                            showError("Invalid public key format: ${e2.message}")
                            isProcessingQR = false
                            return
                        }
                    } else {
                        android.util.Log.e("ScanQRActivity", "Key repair failed: ${repairResult.message}")
                        showError("Invalid public key format: ${e.message}")
                        isProcessingQR = false
                        return
                    }
                }
                
                android.util.Log.d("ScanQRActivity", "Contact created successfully, saving to data manager")
                
                // Save contact to persistent storage
                try {
                    dataManager.addContact(contact)
                    android.util.Log.d("ScanQRActivity", "Contact saved successfully to data manager")
                } catch (e: Exception) {
                    android.util.Log.e("ScanQRActivity", "Failed to save contact: ${e.message}", e)
                    showError("Failed to save contact: ${e.message}")
                    isProcessingQR = false
                    return
                }
                
                // Stop camera to prevent further scanning
                stopCamera()
                
                // Return result to calling activity
                val resultIntent = Intent()
                resultIntent.putExtra("contact_name", publicKeyData.contactName)
                setResult(RESULT_OK, resultIntent)
                
                // Close the activity after a short delay
                binding.root.postDelayed({
                    finish()
                }, 2000)
                
            } else {
                android.util.Log.e("ScanQRActivity", "Failed to parse public key data from QR content")
                showError("Failed to parse public key data from QR code")
                
                // Stop camera to prevent further scanning
                stopCamera()
                
                // Close after delay
                binding.root.postDelayed({
                    finish()
                }, 3000)
            }
        } catch (e: Exception) {
            android.util.Log.e("ScanQRActivity", "Error during public key import: ${e.message}", e)
            showError("Error importing public key: ${e.message}")
            
            // Stop camera to prevent further scanning
            stopCamera()
            
            // Close after delay
            binding.root.postDelayed({
                finish()
            }, 3000)
        } finally {
            isProcessingQR = false
        }
    }
    
    private fun showAuthenticatedMessage(message: String) {
        binding.decryptedMessageText.text = "✅ ${getString(R.string.authentic_message)}\n\n$message"
        binding.decryptedMessageCard.visibility = View.VISIBLE
        showSuccess(getString(R.string.message_verified))
        
        // Also show a Toast as backup in case Snackbar is covered
        Toast.makeText(this, getString(R.string.message_verified), Toast.LENGTH_LONG).show()
    }
    
    private fun hideDecryptedMessage() {
        binding.decryptedMessageCard.visibility = View.GONE
        binding.scanStatus.text = if (isImportMode) "Ready to scan public key QR code" else "Ready to scan"
    }
    
    private fun copyDecryptedMessage() {
        val message = binding.decryptedMessageText.text.toString()
        val clipboard = getSystemService(CLIPBOARD_SERVICE) as android.content.ClipboardManager
        val clip = android.content.ClipData.newPlainText("Decrypted Message", message)
        clipboard.setPrimaryClip(clip)
        
        Toast.makeText(this, "Message copied to clipboard", Toast.LENGTH_SHORT).show()
    }
    
    private fun showSuccess(message: String) {
        Snackbar.make(binding.root, message, Snackbar.LENGTH_LONG)
            .setBackgroundTint(getColor(R.color.success))
            .show()
    }
    
    private fun showError(message: String) {
        Snackbar.make(binding.root, message, Snackbar.LENGTH_LONG)
            .setBackgroundTint(getColor(R.color.error))
            .show()
    }
    
    override fun onDestroy() {
        super.onDestroy()
        cameraExecutor.shutdown()
    }
    
    private inner class QRCodeAnalyzer : ImageAnalysis.Analyzer {
        private val qrCodeReader = QRCodeReader()
        
        @androidx.camera.core.ExperimentalGetImage
        override fun analyze(image: ImageProxy) {
            val buffer = image.planes[0].buffer
            val data = ByteArray(buffer.remaining())
            buffer.get(data)
            
            val source = PlanarYUVLuminanceSource(
                data,
                image.width,
                image.height,
                0,
                0,
                image.width,
                image.height,
                false
            )
            
            val binaryBitmap = BinaryBitmap(HybridBinarizer(source))
            
            try {
                val result = qrCodeReader.decode(binaryBitmap)
                runOnUiThread {
                    processQRCode(result.text)
                }
            } catch (e: Exception) {
                // QR code not found or invalid, continue scanning
            } finally {
                image.close()
            }
        }
    }
} 