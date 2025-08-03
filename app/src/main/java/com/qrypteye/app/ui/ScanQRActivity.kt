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
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

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
    
    companion object {
        private const val CAMERA_PERMISSION_REQUEST = 100
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
            onBackPressed()
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
        // Load user's key pair from persistent storage
        val keyPairData = dataManager.loadKeyPair()
        if (keyPairData != null) {
            try {
                userPrivateKey = cryptoManager.importPrivateKey(keyPairData.privateKeyString)
            } catch (e: Exception) {
                showError("Failed to load user key pair: ${e.message}")
            }
        } else {
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
        if (isProcessingQR) {
            return // Already processing a QR code
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
            binding.scanStatus.text = getString(R.string.verifying_authenticity)
            
            val signedMessage = qrCodeManager.parseSignedEncryptedMessage(qrContent)
            if (signedMessage != null) {
                // Get sender's public key from contacts
                val senderPublicKey = getSenderPublicKey(signedMessage)
                val privateKey = userPrivateKey
                
                if (senderPublicKey == null) {
                    showError(getString(R.string.sender_key_not_found))
                    return
                }
                
                if (privateKey == null) {
                    showError("User key pair not available")
                    return
                }
                
                // Verify and decrypt the message
                val result = cryptoManager.verifyAndDecryptMessage(
                    signedMessage, senderPublicKey, privateKey
                )
                
                when (result) {
                    is CryptoManager.VerificationResult.Success -> {
                        showAuthenticatedMessage(result.message)
                        
                        // Save message to conversation history
                        saveReceivedMessage(result.message, senderPublicKey)
                        
                        // Stop camera to prevent further scanning
                        stopCamera()
                        
                        // Reset processing flag after successful processing
                        isProcessingQR = false
                    }
                    is CryptoManager.VerificationResult.AuthenticationFailed -> {
                        showError(getString(R.string.authenticity_failed))
                        isProcessingQR = false
                    }
                    is CryptoManager.VerificationResult.DecryptionFailed -> {
                        showError("Decryption failed: ${result.error}")
                        isProcessingQR = false
                    }
                }
            } else {
                showError("Failed to parse signed message")
            }
        } catch (e: Exception) {
            showError("Failed to process signed message: ${e.message}")
            isProcessingQR = false
        }
    }
    
    private fun saveReceivedMessage(messageContent: String, senderPublicKey: PublicKey) {
        try {
            // Find the sender contact by public key
            val contacts = dataManager.loadContacts()
            val senderContact = contacts.find { contact ->
                try {
                    val contactPublicKey = cryptoManager.importPublicKey(contact.publicKeyString)
                    contactPublicKey == senderPublicKey
                } catch (e: Exception) {
                    false
                }
            }
            
            if (senderContact != null) {
                val userName = dataManager.getUserName()
                val receivedMessage = Message(
                    id = java.util.UUID.randomUUID().toString(),
                    senderName = senderContact.name,
                    recipientName = userName,
                    content = messageContent,
                    timestamp = System.currentTimeMillis(),
                    isOutgoing = false,
                    isRead = false
                )
                dataManager.addMessage(receivedMessage)
            }
        } catch (e: Exception) {
            // Log error securely without stack trace
        }
    }
    
    private fun getSenderPublicKey(signedMessage: CryptoManager.SignedEncryptedMessage): PublicKey? {
        // TODO: Extract sender information from the message and look up their public key
        // For now, we'll need to implement a way to identify the sender
        // This could be done by including sender info in the signed message
        return try {
            // For demo purposes, try to find any contact's public key
            val contacts = dataManager.loadContacts()
            if (contacts.isNotEmpty()) {
                cryptoManager.importPublicKey(contacts.first().publicKeyString)
            } else {
                null
            }
        } catch (e: Exception) {
            null
        }
    }
    
    private fun importPublicKey(qrContent: String) {
        try {
            val publicKeyData = qrCodeManager.parsePublicKeyData(qrContent)
            if (publicKeyData != null) {
                // Create contact from public key data
                val contact = Contact(
                    name = publicKeyData.contactName,
                    publicKeyString = publicKeyData.publicKey
                )
                
                // Save contact to persistent storage
                dataManager.addContact(contact)
                
                showSuccess("Public key imported for ${publicKeyData.contactName}")
                
                // Also show a Toast as backup
                Toast.makeText(this, "Public key imported for ${publicKeyData.contactName}", Toast.LENGTH_LONG).show()
                
                // Return result to calling activity
                val resultIntent = Intent()
                resultIntent.putExtra("contact_name", publicKeyData.contactName)
                setResult(RESULT_OK, resultIntent)
                
                // Stop camera to prevent further scanning
                stopCamera()
                
                // Close the activity after a short delay
                binding.root.postDelayed({
                    finish()
                }, 2000)
                
            } else {
                showError("Failed to parse public key data")
            }
        } catch (e: Exception) {
            showError("Failed to import public key: ${e.message}")
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