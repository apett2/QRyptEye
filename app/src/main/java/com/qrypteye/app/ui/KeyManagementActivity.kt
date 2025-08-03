package com.qrypteye.app.ui

import android.content.Intent
import android.graphics.Bitmap
import android.net.Uri
import android.os.Bundle
import android.view.View
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.snackbar.Snackbar
import com.qrypteye.app.R
import com.qrypteye.app.crypto.CryptoManager
import com.qrypteye.app.data.DataManager
import com.qrypteye.app.databinding.ActivityKeyManagementBinding
import com.qrypteye.app.qr.QRCodeManager
import java.io.File
import java.io.FileOutputStream

class KeyManagementActivity : AppCompatActivity() {
    
    companion object {
        private const val REQUEST_SCAN_QR = 1001
        private const val REQUEST_SETTINGS = 1002
    }
    
    private lateinit var binding: ActivityKeyManagementBinding
    private var keyPair: java.security.KeyPair? = null
    private lateinit var cryptoManager: com.qrypteye.app.crypto.CryptoManager
    private lateinit var qrCodeManager: com.qrypteye.app.qr.QRCodeManager
    private lateinit var dataManager: com.qrypteye.app.data.DataManager
    private var publicKeyQRBitmap: android.graphics.Bitmap? = null
    
    // Modern Activity Result API
    private val scanQrLauncher = registerForActivityResult(
        androidx.activity.result.contract.ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == RESULT_OK) {
            val data = result.data
            val scannedData = data?.getStringExtra("scanned_data")
            if (!scannedData.isNullOrEmpty()) {
                importPublicKey(scannedData)
            }
        }
    }
    
    private val settingsLauncher = registerForActivityResult(
        androidx.activity.result.contract.ActivityResultContracts.StartActivityForResult()
    ) { _ ->
        // Handle settings result if needed
        loadExistingKeyPair()
    }
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityKeyManagementBinding.inflate(layoutInflater)
        setContentView(binding.root)
        
        cryptoManager = com.qrypteye.app.crypto.CryptoManager()
        qrCodeManager = com.qrypteye.app.qr.QRCodeManager()
        dataManager = com.qrypteye.app.data.DataManager(this)
        
        setSupportActionBar(binding.toolbar)
        supportActionBar?.setDisplayHomeAsUpEnabled(true)
        
        setupUI()
        loadExistingKeyPair()
    }
    
    private fun setupUI() {
        binding.toolbar.setNavigationOnClickListener {
            finish()
        }
        
        binding.generateKeypairButton.setOnClickListener {
            if (keyPair != null) {
                showReplaceKeyPairDialog()
            } else {
                generateNewKeyPair()
            }
        }
        
        binding.exportPublicKeyButton.setOnClickListener {
            exportPublicKey()
        }
        
        binding.sharePublicKeyButton.setOnClickListener {
            sharePublicKeyQR()
        }
        
        binding.importPublicKeyButton.setOnClickListener {
            // Launch QR scanner to import public key
            val intent = Intent(this, ScanQRActivity::class.java)
            intent.putExtra("import_mode", true)
            scanQrLauncher.launch(intent)
        }
        
        binding.settingsButton.setOnClickListener {
            val intent = Intent(this, SettingsActivity::class.java)
            settingsLauncher.launch(intent)
        }
        
        binding.closeQrButton.setOnClickListener {
            hidePublicKeyQR()
        }
    }
    
    private fun showReplaceKeyPairDialog() {
        AlertDialog.Builder(this)
            .setTitle("Replace Key Pair")
            .setMessage("You already have a key pair. Generating a new one will replace the existing one. This will break communication with existing contacts. Are you sure?")
            .setPositiveButton("Replace") { _, _ ->
                generateNewKeyPair()
            }
            .setNegativeButton("Cancel", null)
            .show()
    }
    
    private fun loadExistingKeyPair() {
        try {
            val secureDataManager = com.qrypteye.app.data.SecureDataManager(this)
            
            if (secureDataManager.hasKeyPair()) {
                val loadedKeyPair = secureDataManager.loadKeyPair()
                if (loadedKeyPair != null) {
                    // Store the KeyPair object directly (no serialization)
                    keyPair = loadedKeyPair
                    
                    displayPublicKey()
                    binding.generateKeypairButton.text = "Generate New Keypair"
                    binding.keyStatusText.text = "Key pair loaded from Android Keystore"
                    binding.keyStatusText.setTextColor(getColor(R.color.success))
                } else {
                    binding.generateKeypairButton.text = "Generate Keypair"
                    binding.keyStatusText.text = "Failed to load key pair"
                    binding.keyStatusText.setTextColor(getColor(R.color.error))
                }
            } else {
                binding.generateKeypairButton.text = "Generate Keypair"
                binding.keyStatusText.text = "No key pair found"
                binding.keyStatusText.setTextColor(getColor(R.color.warning))
            }
        } catch (e: Exception) {
            binding.generateKeypairButton.text = "Generate Keypair"
            binding.keyStatusText.text = "Error loading key pair"
            binding.keyStatusText.setTextColor(getColor(R.color.error))
        }
    }
    
    private fun generateNewKeyPair() {
        try {
            binding.generateKeypairButton.isEnabled = false
            binding.generateKeypairButton.text = "Generating..."
            
            // SECURITY: Generate key pair directly in Android Keystore
            // This ensures private keys never leave the secure hardware environment
            val secureDataManager = com.qrypteye.app.data.SecureDataManager(this)
            
            // Generate a new key pair within Android Keystore
            this.keyPair = secureDataManager.generateKeyPair()
            
            // Log key generation event
            if (this.keyPair != null) {
                if (secureDataManager.hasKeyPair()) {
                    secureDataManager.logKeyRotation()
                } else {
                    secureDataManager.logKeyGeneration()
                }
                
                // Display public key
                displayPublicKey()
                showSuccess("Keypair generated and saved securely in Android Keystore")
            } else {
                showError("Failed to generate key pair")
            }
            
        } catch (e: Exception) {
            showError("Failed to generate keypair: ${e.message}")
        } finally {
            binding.generateKeypairButton.isEnabled = true
            binding.generateKeypairButton.text = "Generate New Keypair"
        }
    }
    
    private fun displayPublicKey() {
        keyPair?.let { keyData ->
            binding.publicKeyText.text = cryptoManager.exportPublicKey(keyData.public)
            binding.publicKeyCard.visibility = View.VISIBLE
            binding.keyStatusText.text = "Key pair loaded"
            binding.keyStatusText.setTextColor(getColor(R.color.success))
        }
    }
    
    private fun exportPublicKey() {
        keyPair?.let { keyData ->
            try {
                val intent = Intent(Intent.ACTION_SEND).apply {
                    type = "text/plain"
                    putExtra(Intent.EXTRA_TEXT, cryptoManager.exportPublicKey(keyData.public))
                    putExtra(Intent.EXTRA_SUBJECT, "QRyptEye Public Key")
                }
                
                startActivity(Intent.createChooser(intent, "Export Public Key"))
            } catch (e: Exception) {
                showError("Failed to export public key: ${e.message}")
            }
        }
    }
    
    private fun sharePublicKeyQR() {
        keyPair?.let { keyData ->
            try {
                val userName = dataManager.getUserName()
                if (userName.isEmpty()) {
                    showError("Please set your username in Settings first")
                    return
                }
                
                // Generate QR code for public key
                publicKeyQRBitmap = qrCodeManager.generateQRCodeForPublicKey(
                    cryptoManager.exportPublicKey(keyData.public),
                    userName
                )
                
                if (publicKeyQRBitmap != null) {
                    displayPublicKeyQR()
                } else {
                    showError("Failed to generate QR code")
                }
            } catch (e: Exception) {
                showError("Failed to generate QR code: ${e.message}")
            }
        }
    }
    
    private fun displayPublicKeyQR() {
        publicKeyQRBitmap?.let { bitmap ->
            binding.publicKeyQrImage.setImageBitmap(bitmap)
            binding.publicKeyQrCard.visibility = View.VISIBLE
        }
    }
    
    private fun hidePublicKeyQR() {
        binding.publicKeyQrCard.visibility = View.GONE
    }
    
    private fun importPublicKey(scannedData: String) {
        try {
            // Try to parse the scanned data as a contact using QRCodeManager
            val publicKeyData = qrCodeManager.parsePublicKeyData(scannedData)
            
            if (publicKeyData != null) {
                val contact = com.qrypteye.app.data.Contact.createContactFromString(
                    publicKeyData.contactName, 
                    publicKeyData.publicKey
                )
                
                // Save the contact
                val secureDataManager = com.qrypteye.app.data.SecureDataManager(this)
                secureDataManager.addContact(contact)
                
                showSuccess("Successfully imported public key for ${contact.name}")
            } else {
                // Fallback: Try to parse as legacy format
                try {
                    val gson = com.google.gson.Gson()
                    val contactData = gson.fromJson(scannedData, Map::class.java)
                    
                    val name = contactData["name"] as? String
                    val publicKeyString = contactData["publicKeyString"] as? String
                    
                    if (name != null && publicKeyString != null) {
                        val contact = com.qrypteye.app.data.Contact.createContactFromString(name, publicKeyString)
                        
                        // Save the contact
                        val secureDataManager = com.qrypteye.app.data.SecureDataManager(this)
                        secureDataManager.addContact(contact)
                        
                        showSuccess("Successfully imported public key for ${contact.name}")
                    } else {
                        showError("Invalid QR code format. Expected contact information with name and publicKeyString.")
                    }
                } catch (e: Exception) {
                    showError("Invalid QR code format. Could not parse contact information.")
                }
            }
        } catch (e: Exception) {
            showError("Error importing public key: ${e.message}")
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