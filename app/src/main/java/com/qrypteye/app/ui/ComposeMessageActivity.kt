package com.qrypteye.app.ui

import android.content.Intent
import android.graphics.Bitmap
import android.net.Uri
import android.os.Bundle
import android.text.Editable
import android.text.TextWatcher
import android.view.View
import android.widget.ArrayAdapter
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import com.google.android.material.snackbar.Snackbar
import com.qrypteye.app.R
import com.qrypteye.app.crypto.CryptoManager
import com.qrypteye.app.data.Contact
import com.qrypteye.app.data.DataManager
import com.qrypteye.app.data.Message
import com.qrypteye.app.databinding.ActivityComposeMessageBinding
import com.qrypteye.app.qr.QRCodeManager
import java.io.File
import java.io.FileOutputStream
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.util.*

class ComposeMessageActivity : AppCompatActivity() {
    
    private lateinit var binding: ActivityComposeMessageBinding
    private lateinit var cryptoManager: CryptoManager
    private lateinit var qrCodeManager: QRCodeManager
    private lateinit var dataManager: DataManager
    
    private var selectedContact: Contact? = null
    private var qrCodeBitmap: Bitmap? = null
    private var userPrivateKey: PrivateKey? = null
    private var isEncrypting: Boolean = false
    
    companion object {
        private val MAX_MESSAGE_LENGTH = QRCodeManager.MAX_MESSAGE_LENGTH
        private const val REQUEST_CODE_IMPORT_CONTACT = 100
        private val secureRandom = SecureRandom()
        
        private fun generateSecureId(): String {
            val bytes = ByteArray(16)
            secureRandom.nextBytes(bytes)
            return android.util.Base64.encodeToString(bytes, android.util.Base64.URL_SAFE or android.util.Base64.NO_PADDING)
        }
    }
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityComposeMessageBinding.inflate(layoutInflater)
        setContentView(binding.root)
        
        cryptoManager = CryptoManager()
        qrCodeManager = QRCodeManager()
        dataManager = DataManager(this)
        
        setSupportActionBar(binding.toolbar)
        supportActionBar?.setDisplayHomeAsUpEnabled(true)
        
        setupUI()
        loadContacts()
        loadUserKeyPair()
        setupCharacterCounter()
        
        // Check if a contact was pre-selected
        val preSelectedContact = intent.getStringExtra("selected_contact")
        if (preSelectedContact != null) {
            // Find and select the contact
            val contacts = dataManager.loadContacts()
            val contact = contacts.find { it.name == preSelectedContact }
            if (contact != null) {
                selectedContact = contact
                binding.recipientSpinner.tag = contact
                binding.recipientSpinner.setText(contact.name, false)
            }
        }
    }
    
    private fun setupUI() {
        binding.toolbar.setNavigationOnClickListener {
            finish()
        }
        
        binding.encryptButton.setOnClickListener {
            encryptAndGenerateQR()
        }
    }
    
    private fun setupCharacterCounter() {
        binding.messageEditText.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
            override fun afterTextChanged(s: Editable?) {
                updateCharacterCounter(s?.length ?: 0)
            }
        })
        
        // Set initial character limit
        binding.messageEditText.filters = arrayOf(android.text.InputFilter.LengthFilter(MAX_MESSAGE_LENGTH))
        updateCharacterCounter(0)
    }
    
    private fun updateCharacterCounter(currentLength: Int) {
        val remaining = qrCodeManager.getRemainingCharacters(currentLength)
        val isWithinLimit = qrCodeManager.isMessageWithinCapacity(currentLength)
        
        // Update character counter text
        binding.characterCounter.text = "$currentLength/$MAX_MESSAGE_LENGTH"
        
        // Update character counter color based on remaining characters
        val colorRes = when {
            remaining <= 50 -> R.color.error
            remaining <= 100 -> R.color.warning
            else -> R.color.text_secondary
        }
        binding.characterCounter.setTextColor(ContextCompat.getColor(this, colorRes))
        
        // Update encrypt button state
        binding.encryptButton.isEnabled = isWithinLimit && currentLength > 0 && !isEncrypting
        
        // Show detailed QR code information
        if (currentLength > 0) {
            val capacity = qrCodeManager.calculateQRCodeCapacity(currentLength)
            val qrSize = qrCodeManager.estimateQRCodeSize(currentLength)
            
            // Build detailed QR info string
            val qrInfo = buildString {
                append("QR: ${capacity.recommendedVersion} (${getVersionSize(capacity.recommendedVersion)})")
                append(" • ${capacity.recommendedErrorCorrection}")
                append(" • ${capacity.estimatedJsonSize} bytes")
            }
            
            binding.qrSizeIndicator.text = qrInfo
            
            // Set color based on QR size
            val qrColorRes = when (qrSize) {
                QRCodeManager.QRCodeSize.SMALL -> R.color.success
                QRCodeManager.QRCodeSize.MEDIUM -> R.color.text_secondary
                QRCodeManager.QRCodeSize.LARGE -> R.color.warning
                QRCodeManager.QRCodeSize.TOO_LARGE -> R.color.error
            }
            binding.qrSizeIndicator.setTextColor(ContextCompat.getColor(this, qrColorRes))
        } else {
            binding.qrSizeIndicator.text = ""
        }
    }
    
    private fun getVersionSize(version: Int): String {
        return when (version) {
            25 -> "512×512"
            30 -> "672×672"
            40 -> "896×896"
            else -> "Unknown"
        }
    }
    
    private fun loadContacts() {
        // Load contacts from persistent storage
        val contacts = dataManager.loadContacts()
        
        android.util.Log.d("ComposeMessageActivity", "Loaded ${contacts.size} contacts from data manager")
        
        if (contacts.isEmpty()) {
            // Show message when no contacts are available
            binding.recipientLayout.hint = "No contacts available"
            binding.recipientSpinner.setText("", false)
            binding.recipientSpinner.isEnabled = false
            binding.encryptButton.isEnabled = false
            showError("No contacts found. Please import public keys first.")
        } else {
            // Validate contacts and filter out invalid ones
            val validContacts = contacts.filter { contact ->
                android.util.Log.d("ComposeMessageActivity", "Validating contact: ${contact.name}")
                if (contact.isValid()) {
                    android.util.Log.d("ComposeMessageActivity", "Contact ${contact.name} is valid")
                    true
                } else {
                    // Log invalid contact for debugging
                    val validationResult = contact.getValidationResult()
                    android.util.Log.e("ComposeMessageActivity", "Contact ${contact.name} is invalid: ${validationResult.message}")
                    showError("Invalid contact '${contact.name}': ${validationResult.message}")
                    false
                }
            }
            
            android.util.Log.d("ComposeMessageActivity", "Found ${validContacts.size} valid contacts out of ${contacts.size} total")
            
            if (validContacts.isEmpty()) {
                // All contacts are invalid
                binding.recipientLayout.hint = "No valid contacts available"
                binding.recipientSpinner.setText("", false)
                binding.recipientSpinner.isEnabled = false
                binding.encryptButton.isEnabled = false
                showError("All contacts have invalid public keys. Please re-import them.")
            } else {
                val contactNames = validContacts.map { it.name }
                val adapter = ArrayAdapter(this, android.R.layout.simple_dropdown_item_1line, contactNames)
                binding.recipientSpinner.setAdapter(adapter)
                binding.recipientLayout.hint = "Select recipient"
                binding.recipientSpinner.isEnabled = true
                
                binding.recipientSpinner.setOnItemClickListener { _, _, position, _ ->
                    selectedContact = validContacts[position]
                    // Store the selected contact to prevent timeout issues
                    binding.recipientSpinner.tag = selectedContact
                }
            }
        }
    }
    
    private fun loadUserKeyPair() {
        // Load user's key pair from Android Keystore
        val keyPair = dataManager.loadKeyPair()
        if (keyPair != null) {
            try {
                // SECURITY: Private key is accessed directly from KeyPair object
                // No serialization or string conversion
                userPrivateKey = keyPair.private
            } catch (e: Exception) {
                showError("Failed to load user key pair: ${e.message}")
            }
        } else {
            showError("No key pair found. Please generate keys first.")
        }
    }
    
    private fun encryptAndGenerateQR() {
        val message = binding.messageEditText.text.toString().trim()
        val recipient = selectedContact ?: binding.recipientSpinner.tag as? Contact
        val privateKey = userPrivateKey
        
        if (message.isEmpty()) {
            showError("Please enter a message")
            return
        }
        
        // SECURITY: Validate message content before encryption
        val contentValidation = com.qrypteye.app.data.ContactValidator.validateMessageContent(message, MAX_MESSAGE_LENGTH)
        if (contentValidation !is com.qrypteye.app.data.ContactValidator.MessageContentValidationResult.Valid) {
            showError("Message content validation failed: ${contentValidation.message}")
            return
        }
        
        // Use validated and normalized content
        val validatedMessage = contentValidation.normalizedContent
        
        if (recipient == null) {
            showError("Please select a recipient")
            return
        }
        
        // Validate recipient contact before using it
        if (!recipient.isValid()) {
            val validationResult = recipient.getValidationResult()
            showError("Invalid recipient contact: ${validationResult.message}")
            return
        }
        
        if (privateKey == null) {
            showError("User key pair not available. Please generate keys first.")
            return
        }
        
        if (!qrCodeManager.isMessageWithinCapacity(validatedMessage.length)) {
            showError("Message is too long. Maximum ${MAX_MESSAGE_LENGTH} characters allowed.")
            return
        }
        
        if (isEncrypting) {
            showError("Already encrypting a message. Please wait.")
            return
        }
        
        isEncrypting = true
        binding.encryptButton.isEnabled = false
        
        try {
            // Import recipient's public key (already validated above)
            val publicKey = cryptoManager.importPublicKey(recipient.publicKeyString)
            
            // Get user's name and public key for sender identification
            val currentUserName = dataManager.getUserName()
            val userKeyPair = dataManager.loadKeyPair()
            if (userKeyPair == null) {
                showError("User key pair not available")
                return
            }
            
            // Create signed encrypted message with sender information
            val signedMessage = cryptoManager.createSignedEncryptedMessage(
                validatedMessage, publicKey, privateKey, currentUserName, userKeyPair.public
            )
            
            // Generate QR code
            qrCodeBitmap = qrCodeManager.generateQRCodeForSignedMessage(signedMessage)
            
            if (qrCodeBitmap != null) {
                displayQRCode()
                showSuccess("Message encrypted and signed successfully")
                
                // Save message to conversation history with cryptographic signature
                val userName = dataManager.getUserName()
                val secureMessage = dataManager.createSignedMessage(message, recipient.name, userName)
                
                if (secureMessage != null) {
                    dataManager.addMessage(secureMessage)
                } else {
                    showError("Failed to sign message for storage")
                }
                
            } else {
                showError("Failed to generate QR code")
            }
            
        } catch (e: Exception) {
            showError("Encryption failed: ${e.message}")
        } finally {
            isEncrypting = false
            binding.encryptButton.isEnabled = true
        }
    }
    
    private fun displayQRCode() {
        // Save QR bitmap to file to avoid binder transaction error
        qrCodeBitmap?.let { bitmap ->
            try {
                val fileName = "qrypteye_message_${System.currentTimeMillis()}.png"
                val file = File(getExternalFilesDir(null), fileName)
                val outputStream = FileOutputStream(file)
                bitmap.compress(Bitmap.CompressFormat.PNG, 100, outputStream)
                outputStream.close()
                
                // Launch full-screen QR activity with file path instead of bitmap
                val intent = Intent(this, QRCodeFullScreenActivity::class.java).apply {
                    putExtra(QRCodeFullScreenActivity.EXTRA_QR_FILE_PATH, file.absolutePath)
                    // Don't include message preview to prevent plain text exposure
                }
                startActivity(intent)
                
                // Clear the message after successful encryption
                binding.messageEditText.text?.clear()
                
            } catch (e: Exception) {
                showError("Failed to save QR code: ${e.message}")
            }
        } ?: run {
            showError("No QR code generated")
        }
    }
    
    private fun saveQRCode() {
        qrCodeBitmap?.let { bitmap ->
            try {
                val fileName = "qrypteye_message_${System.currentTimeMillis()}.png"
                val file = File(getExternalFilesDir(null), fileName)
                val outputStream = FileOutputStream(file)
                bitmap.compress(Bitmap.CompressFormat.PNG, 100, outputStream)
                outputStream.close()
                
                showSuccess("QR code saved to ${file.name}")
            } catch (e: Exception) {
                showError("Failed to save QR code: ${e.message}")
            }
        }
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
} 