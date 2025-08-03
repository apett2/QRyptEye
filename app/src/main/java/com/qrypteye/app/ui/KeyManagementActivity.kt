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
import com.qrypteye.app.data.KeyPairData
import com.qrypteye.app.databinding.ActivityKeyManagementBinding
import com.qrypteye.app.qr.QRCodeManager
import java.io.File
import java.io.FileOutputStream

class KeyManagementActivity : AppCompatActivity() {
    
    private lateinit var binding: ActivityKeyManagementBinding
    private lateinit var cryptoManager: CryptoManager
    private lateinit var qrCodeManager: QRCodeManager
    private lateinit var dataManager: DataManager
    
    private var keyPairData: KeyPairData? = null
    private var publicKeyQRBitmap: Bitmap? = null
    
    companion object {
        private const val REQUEST_SCAN_QR = 1001
        private const val REQUEST_SETTINGS = 1002
    }
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityKeyManagementBinding.inflate(layoutInflater)
        setContentView(binding.root)
        
        cryptoManager = CryptoManager()
        qrCodeManager = QRCodeManager()
        dataManager = DataManager(this)
        
        setSupportActionBar(binding.toolbar)
        supportActionBar?.setDisplayHomeAsUpEnabled(true)
        
        setupUI()
        loadExistingKeyPair()
    }
    
    private fun setupUI() {
        binding.toolbar.setNavigationOnClickListener {
            onBackPressed()
        }
        
        binding.generateKeypairButton.setOnClickListener {
            if (keyPairData != null) {
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
            startActivityForResult(intent, REQUEST_SCAN_QR)
        }
        
        binding.settingsButton.setOnClickListener {
            val intent = Intent(this, SettingsActivity::class.java)
            startActivityForResult(intent, REQUEST_SETTINGS)
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
        keyPairData = dataManager.loadKeyPair()
        if (keyPairData != null) {
            displayPublicKey()
            binding.generateKeypairButton.text = "Generate New Keypair"
            binding.keyStatusText.text = "Key pair loaded"
            binding.keyStatusText.setTextColor(getColor(R.color.success))
        } else {
            binding.generateKeypairButton.text = "Generate Keypair"
            binding.keyStatusText.text = "No key pair found"
            binding.keyStatusText.setTextColor(getColor(R.color.warning))
        }
    }
    
    private fun generateNewKeyPair() {
        try {
            binding.generateKeypairButton.isEnabled = false
            binding.generateKeypairButton.text = "Generating..."
            
            // Generate new key pair
            val keyPair = cryptoManager.generateKeyPair()
            keyPairData = KeyPairData.create(keyPair)
            
            // Save to persistent storage
            dataManager.saveKeyPair(keyPairData!!)
            
            // Display public key
            displayPublicKey()
            
            showSuccess("Keypair generated and saved successfully")
            
        } catch (e: Exception) {
            showError("Failed to generate keypair: ${e.message}")
        } finally {
            binding.generateKeypairButton.isEnabled = true
            binding.generateKeypairButton.text = "Generate New Keypair"
        }
    }
    
    private fun displayPublicKey() {
        keyPairData?.let { keyData ->
            binding.publicKeyText.text = keyData.publicKeyString
            binding.publicKeyCard.visibility = View.VISIBLE
            binding.keyStatusText.text = "Key pair loaded"
            binding.keyStatusText.setTextColor(getColor(R.color.success))
        }
    }
    
    private fun exportPublicKey() {
        keyPairData?.let { keyData ->
            try {
                val intent = Intent(Intent.ACTION_SEND).apply {
                    type = "text/plain"
                    putExtra(Intent.EXTRA_TEXT, keyData.publicKeyString)
                    putExtra(Intent.EXTRA_SUBJECT, "QRyptEye Public Key")
                }
                
                startActivity(Intent.createChooser(intent, "Export Public Key"))
            } catch (e: Exception) {
                showError("Failed to export public key: ${e.message}")
            }
        }
    }
    
    private fun sharePublicKeyQR() {
        keyPairData?.let { keyData ->
            try {
                val userName = dataManager.getUserName()
                if (userName.isEmpty()) {
                    showError("Please set your username in Settings first")
                    return
                }
                
                // Generate QR code for public key
                publicKeyQRBitmap = qrCodeManager.generateQRCodeForPublicKey(
                    keyData.publicKeyString,
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
    
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        
        if (requestCode == REQUEST_SCAN_QR && resultCode == RESULT_OK) {
            // Handle successful QR scan for importing public key
            val contactName = data?.getStringExtra("contact_name")
            if (contactName != null) {
                showSuccess("Successfully imported public key for $contactName")
            }
        } else if (requestCode == REQUEST_SETTINGS && resultCode == RESULT_OK) {
            // Settings were updated, refresh the UI if needed
            showSuccess("Settings updated successfully")
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