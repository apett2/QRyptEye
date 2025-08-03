package com.qrypteye.app.qr

import android.graphics.Bitmap
import android.graphics.Color
import com.google.gson.Gson
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.WriterException
import com.google.zxing.common.BitMatrix
import com.google.zxing.qrcode.QRCodeWriter
import com.qrypteye.app.crypto.CryptoManager
import java.util.*

class QRCodeManager {
    
    companion object {
        private const val QR_CODE_SIZE = 512
        private const val MARGIN = 0
        private val gson = Gson()
        
        // QR Code Version 25 capacities (512x512 pixels) in bytes
        // Based on actual QR code specifications for binary data
        private const val QR_V25_L = 1273  // Low error correction
        private const val QR_V25_M = 1001  // Medium error correction (recommended)
        private const val QR_V25_Q = 729   // High error correction
        private const val QR_V25_H = 553   // Highest error correction
        
        // QR Code Version 30 capacities (672x672 pixels) in bytes
        private const val QR_V30_L = 2086
        private const val QR_V30_M = 1652
        private const val QR_V30_Q = 1218
        private const val QR_V30_H = 984
        
        // JSON overhead estimation for SignedEncryptedMessage
        // Structure: {"encryptedMessage":{"encryptedData":"...","encryptedKey":"...","iv":"...","timestamp":123},"signature":"..."}
        private const val JSON_OVERHEAD_BYTES = 150  // Base JSON structure overhead
        private const val BASE64_OVERHEAD = 1.33     // Base64 encoding increases size by ~33%
        private const val ENCRYPTION_OVERHEAD = 1.5  // Encryption adds padding and metadata
        
        // Recommended capacity using Version 25 with Medium error correction
        // Conservative estimate accounting for JSON overhead and encryption
        val MAX_MESSAGE_LENGTH = calculateMaxMessageLength()
        
        private fun calculateMaxMessageLength(): Int {
            // Available bytes for actual message content
            val availableBytes = QR_V25_M - JSON_OVERHEAD_BYTES
            
            // Account for Base64 encoding and encryption overhead
            val effectiveBytes = (availableBytes / (BASE64_OVERHEAD * ENCRYPTION_OVERHEAD)).toInt()
            
            // Convert to character limit (assuming UTF-8, 1 byte per character average)
            return effectiveBytes
        }
    }
    
    /**
     * Calculate actual QR code capacity for a given message
     */
    fun calculateQRCodeCapacity(messageLength: Int): QRCodeCapacity {
        val jsonSize = estimateJsonSize(messageLength)
        
        return QRCodeCapacity(
            messageLength = messageLength,
            estimatedJsonSize = jsonSize,
            qrVersion25L = jsonSize <= QR_V25_L,
            qrVersion25M = jsonSize <= QR_V25_M,
            qrVersion25Q = jsonSize <= QR_V25_Q,
            qrVersion25H = jsonSize <= QR_V25_H,
            qrVersion30L = jsonSize <= QR_V30_L,
            qrVersion30M = jsonSize <= QR_V30_M,
            qrVersion30Q = jsonSize <= QR_V30_Q,
            qrVersion30H = jsonSize <= QR_V30_H,
            recommendedVersion = getRecommendedVersion(jsonSize),
            recommendedErrorCorrection = getRecommendedErrorCorrection(jsonSize)
        )
    }
    
    /**
     * Estimate JSON size for a given message length
     */
    private fun estimateJsonSize(messageLength: Int): Int {
        // Base JSON structure overhead
        var totalSize = JSON_OVERHEAD_BYTES
        
        // Encrypted message size (message + encryption overhead + Base64)
        val encryptedMessageSize = (messageLength * ENCRYPTION_OVERHEAD * BASE64_OVERHEAD).toInt()
        totalSize += encryptedMessageSize
        
        // Signature size (typically 256 bytes for RSA-2048, Base64 encoded)
        val signatureSize = (256 * BASE64_OVERHEAD).toInt()
        totalSize += signatureSize
        
        return totalSize
    }
    
    /**
     * Get recommended QR code version for given size
     */
    private fun getRecommendedVersion(jsonSize: Int): Int {
        return when {
            jsonSize <= QR_V25_M -> 25  // 512x512, good balance
            jsonSize <= QR_V30_M -> 30  // 672x672, larger but still manageable
            else -> 40  // Maximum size, may be hard to scan
        }
    }
    
    /**
     * Get recommended error correction level for given size
     */
    private fun getRecommendedErrorCorrection(jsonSize: Int): String {
        return when {
            jsonSize <= QR_V25_H -> "H"  // Highest error correction
            jsonSize <= QR_V25_Q -> "Q"  // High error correction
            jsonSize <= QR_V25_M -> "M"  // Medium error correction (recommended)
            else -> "L"  // Low error correction
        }
    }
    
    /**
     * Generate QR code for signed encrypted message
     */
    fun generateQRCodeForSignedMessage(signedMessage: CryptoManager.SignedEncryptedMessage): Bitmap? {
        val jsonString = gson.toJson(signedMessage)
        return generateQRCode(jsonString)
    }
    
    /**
     * Generate QR code for public key
     */
    fun generateQRCodeForPublicKey(publicKey: String, contactName: String): Bitmap? {
        val publicKeyData = PublicKeyData(publicKey, contactName, System.currentTimeMillis())
        val jsonString = gson.toJson(publicKeyData)
        return generateQRCode(jsonString)
    }
    
    /**
     * Parse QR code content as signed encrypted message
     */
    fun parseSignedEncryptedMessage(qrContent: String): CryptoManager.SignedEncryptedMessage? {
        return try {
            // Validate input length to prevent DoS attacks
            if (qrContent.length > 10000) {
                return null
            }
            
            val result = gson.fromJson(qrContent, CryptoManager.SignedEncryptedMessage::class.java)
            
            // Validate parsed result
            if (result?.encryptedMessage?.encryptedData.isNullOrEmpty() ||
                result?.encryptedMessage?.encryptedKey.isNullOrEmpty() ||
                result?.encryptedMessage?.iv.isNullOrEmpty() ||
                result?.signature.isNullOrEmpty()) {
                return null
            }
            
            result
        } catch (e: Exception) {
            null
        }
    }
    
    /**
     * Parse QR code content as public key data
     */
    fun parsePublicKeyData(qrContent: String): PublicKeyData? {
        return try {
            // Validate input length to prevent DoS attacks
            if (qrContent.length > 5000) {
                return null
            }
            
            val result = gson.fromJson(qrContent, PublicKeyData::class.java)
            
            // Validate parsed result
            if (result?.publicKey.isNullOrEmpty() || result?.contactName.isNullOrEmpty()) {
                return null
            }
            
            result
        } catch (e: Exception) {
            null
        }
    }
    
    /**
     * Check if QR code contains signed encrypted message
     */
    fun isSignedEncryptedMessage(qrContent: String): Boolean {
        return try {
            val data = gson.fromJson(qrContent, CryptoManager.SignedEncryptedMessage::class.java)
            data.encryptedMessage.encryptedData.isNotEmpty() && 
            data.encryptedMessage.encryptedKey.isNotEmpty() && 
            data.encryptedMessage.iv.isNotEmpty() &&
            data.signature.isNotEmpty()
        } catch (e: Exception) {
            false
        }
    }
    
    /**
     * Check if QR code contains public key data
     */
    fun isPublicKeyData(qrContent: String): Boolean {
        return try {
            val data = gson.fromJson(qrContent, PublicKeyData::class.java)
            data.publicKey.isNotEmpty() && data.contactName.isNotEmpty()
        } catch (e: Exception) {
            false
        }
    }
    
    /**
     * Get QR code type for display purposes
     */
    fun getQRCodeType(qrContent: String): QRCodeType {
        return when {
            isSignedEncryptedMessage(qrContent) -> QRCodeType.SIGNED_ENCRYPTED_MESSAGE
            isPublicKeyData(qrContent) -> QRCodeType.PUBLIC_KEY
            else -> QRCodeType.UNKNOWN
        }
    }
    
    /**
     * Calculate estimated QR code size for a given message length
     */
    fun estimateQRCodeSize(messageLength: Int): QRCodeSize {
        val capacity = calculateQRCodeCapacity(messageLength)
        return when {
            capacity.qrVersion25M -> QRCodeSize.SMALL
            capacity.qrVersion30M -> QRCodeSize.MEDIUM
            capacity.qrVersion30L -> QRCodeSize.LARGE
            else -> QRCodeSize.TOO_LARGE
        }
    }
    
    /**
     * Check if message length is within QR code capacity
     */
    fun isMessageWithinCapacity(messageLength: Int): Boolean {
        return messageLength <= MAX_MESSAGE_LENGTH
    }
    
    /**
     * Get remaining characters available
     */
    fun getRemainingCharacters(currentLength: Int): Int {
        return maxOf(0, MAX_MESSAGE_LENGTH - currentLength)
    }
    
    /**
     * Get detailed capacity information for a message
     */
    fun getCapacityInfo(messageLength: Int): String {
        val capacity = calculateQRCodeCapacity(messageLength)
        return buildString {
            append("Message: ${messageLength} chars\n")
            append("Estimated JSON: ${capacity.estimatedJsonSize} bytes\n")
            append("QR Version: ${capacity.recommendedVersion} (${getVersionSize(capacity.recommendedVersion)})\n")
            append("Error Correction: ${capacity.recommendedErrorCorrection}")
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
    
    private fun generateQRCode(content: String): Bitmap? {
        return try {
            val hints = EnumMap<EncodeHintType, Any>(EncodeHintType::class.java)
            hints[EncodeHintType.MARGIN] = MARGIN
            
            val writer = QRCodeWriter()
            val bitMatrix: BitMatrix = writer.encode(
                content,
                BarcodeFormat.QR_CODE,
                QR_CODE_SIZE,
                QR_CODE_SIZE,
                hints
            )
            
            val width = bitMatrix.width
            val height = bitMatrix.height
            val bitmap = Bitmap.createBitmap(width, height, Bitmap.Config.ARGB_8888)
            
            for (x in 0 until width) {
                for (y in 0 until height) {
                    bitmap.setPixel(x, y, if (bitMatrix[x, y]) Color.BLACK else Color.WHITE)
                }
            }
            
            bitmap
        } catch (e: WriterException) {
            // Log error securely without stack trace
            null
        }
    }
    
    data class PublicKeyData(
        val publicKey: String,
        val contactName: String,
        val timestamp: Long
    )
    
    data class QRCodeCapacity(
        val messageLength: Int,
        val estimatedJsonSize: Int,
        val qrVersion25L: Boolean,
        val qrVersion25M: Boolean,
        val qrVersion25Q: Boolean,
        val qrVersion25H: Boolean,
        val qrVersion30L: Boolean,
        val qrVersion30M: Boolean,
        val qrVersion30Q: Boolean,
        val qrVersion30H: Boolean,
        val recommendedVersion: Int,
        val recommendedErrorCorrection: String
    )
    
    enum class QRCodeType {
        SIGNED_ENCRYPTED_MESSAGE,
        PUBLIC_KEY,
        UNKNOWN
    }
    
    enum class QRCodeSize {
        SMALL,      // Easy to scan
        MEDIUM,     // Good balance
        LARGE,      // May be harder to scan
        TOO_LARGE   // Exceeds capacity
    }
} 