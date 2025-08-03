package com.qrypteye.app.ui

import android.graphics.Bitmap
import android.os.Bundle
import android.view.View
import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.snackbar.Snackbar
import com.qrypteye.app.R
import com.qrypteye.app.databinding.ActivityQrCodeFullScreenBinding
import java.io.File
import java.io.FileOutputStream

class QRCodeFullScreenActivity : AppCompatActivity() {
    
    private lateinit var binding: ActivityQrCodeFullScreenBinding
    private var qrCodeBitmap: Bitmap? = null
    private var qrCodeFilePath: String? = null
    
    companion object {
        const val EXTRA_QR_BITMAP = "qr_bitmap"
        const val EXTRA_QR_FILE_PATH = "qr_file_path"
        const val EXTRA_MESSAGE_PREVIEW = "message_preview"
    }
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityQrCodeFullScreenBinding.inflate(layoutInflater)
        setContentView(binding.root)
        
        // Hide system UI for full screen experience
        hideSystemUI()
        
        setupUI()
        loadQRCode()
    }
    
    private fun setupUI() {
        binding.toolbar.setNavigationOnClickListener {
            finish()
        }
        
        binding.saveQrButton.setOnClickListener {
            saveQRCode()
        }
        
        binding.closeButton.setOnClickListener {
            finish()
        }
        
        binding.shareButton.setOnClickListener {
            shareQRCode()
        }
    }
    
    private fun loadQRCode() {
        // Get QR file path from intent
        qrCodeFilePath = intent.getStringExtra(EXTRA_QR_FILE_PATH)
        
        if (!qrCodeFilePath.isNullOrEmpty()) {
            try {
                val file = File(qrCodeFilePath!!)
                if (file.exists()) {
                    qrCodeBitmap = android.graphics.BitmapFactory.decodeFile(file.absolutePath)
                    binding.qrCodeImage.setImageBitmap(qrCodeBitmap)
                    
                    // Show message preview if provided
                    val messagePreview = intent.getStringExtra(EXTRA_MESSAGE_PREVIEW)
                    if (!messagePreview.isNullOrEmpty()) {
                        binding.messagePreview.text = "Message: $messagePreview"
                        binding.messagePreview.visibility = View.VISIBLE
                    } else {
                        binding.messagePreview.visibility = View.GONE
                    }
                } else {
                    showError("QR code file not found")
                    finish()
                }
            } catch (e: Exception) {
                showError("Failed to load QR code: ${e.message}")
                finish()
            }
        } else {
            showError("No QR code file path provided")
            finish()
        }
    }
    
    private fun saveQRCode() {
        qrCodeFilePath?.let { filePath ->
            try {
                val sourceFile = File(filePath)
                if (sourceFile.exists()) {
                    val fileName = "qrypteye_message_${System.currentTimeMillis()}.png"
                    val destFile = File(getExternalFilesDir(null), fileName)
                    
                    sourceFile.copyTo(destFile, overwrite = true)
                    
                    showSuccess("QR code saved to ${destFile.name}")
                } else {
                    showError("QR code file not found")
                }
            } catch (e: Exception) {
                showError("Failed to save QR code: ${e.message}")
            }
        } ?: run {
            showError("No QR code file available")
        }
    }
    
    private fun shareQRCode() {
        qrCodeFilePath?.let { filePath ->
            try {
                val sourceFile = File(filePath)
                if (sourceFile.exists()) {
                    val intent = android.content.Intent(android.content.Intent.ACTION_SEND).apply {
                        type = "image/png"
                        putExtra(android.content.Intent.EXTRA_STREAM, androidx.core.content.FileProvider.getUriForFile(
                            this@QRCodeFullScreenActivity,
                            "${packageName}.fileprovider",
                            sourceFile
                        ))
                        putExtra(android.content.Intent.EXTRA_SUBJECT, "QRyptEye Encrypted Message")
                        putExtra(android.content.Intent.EXTRA_TEXT, "Encrypted message QR code from QRyptEye")
                        addFlags(android.content.Intent.FLAG_GRANT_READ_URI_PERMISSION)
                    }
                    
                    startActivity(android.content.Intent.createChooser(intent, "Share QR Code"))
                } else {
                    showError("QR code file not found")
                }
            } catch (e: Exception) {
                showError("Failed to share QR code: ${e.message}")
            }
        } ?: run {
            showError("No QR code file available")
        }
    }
    
    private fun hideSystemUI() {
        // Hide the status bar and navigation bar
        window.decorView.systemUiVisibility = (View.SYSTEM_UI_FLAG_FULLSCREEN
                or View.SYSTEM_UI_FLAG_HIDE_NAVIGATION
                or View.SYSTEM_UI_FLAG_IMMERSIVE_STICKY)
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
    
    override fun onWindowFocusChanged(hasFocus: Boolean) {
        super.onWindowFocusChanged(hasFocus)
        if (hasFocus) {
            hideSystemUI()
        }
    }
} 