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
        
        // Security validation constants
        private const val MIN_QR_CONTENT_LENGTH = 1  // Allow single character messages
        private const val MAX_SIGNED_MESSAGE_LENGTH = 425  // Experimentally determined maximum for MESSAGE CONTENT only
        private const val MAX_SIGNED_MESSAGE_QR_LENGTH = 2000  // Higher limit for signed message QR codes (includes encryption metadata)
        private const val MAX_PUBLIC_KEY_QR_LENGTH = 5000  // Higher limit for public key QR codes
        private const val MAX_PUBLIC_KEY_LENGTH = 5000
        private const val MAX_NAME_LENGTH = 100
        private const val MAX_ENCRYPTED_FIELD_SIZE = 1024 * 1024 // 1MB
        private const val MAX_IV_SIZE = 1024 // 1KB
        private const val MAX_AUTH_TAG_SIZE = 1024 // 1KB
        private const val MAX_HASH_SIZE = 1024 // 1KB
        private const val MAX_SIGNATURE_SIZE = 1024 // 1KB
        private const val MAX_FUTURE_TIMESTAMP_MS = 5 * 60 * 1000L // 5 minutes
        
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
        // Based on experimental testing showing 425 characters is the practical maximum
        val MAX_MESSAGE_LENGTH = 425
        
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
            // 1. Type-specific input validation
            if (!isValidQRContent(qrContent, QRCodeType.SIGNED_ENCRYPTED_MESSAGE)) {
                android.util.Log.w("QRCodeManager", "QR content validation failed for signed message type")
                return null
            }
            
            // 2. JSON structure validation
            if (!isValidJsonWithRequiredFields(qrContent, listOf("encryptedMessage", "signature"))) {
                android.util.Log.w("QRCodeManager", "JSON structure validation failed")
                return null
            }
            
            // 3. Parse JSON
            val result = gson.fromJson(qrContent, CryptoManager.SignedEncryptedMessage::class.java)
            
            // 4. Post-parse validation
            if (!isValidSignedMessage(result)) {
                android.util.Log.w("QRCodeManager", "Signed message validation failed")
                return null
            }
            
            result
        } catch (e: Exception) {
            android.util.Log.e("QRCodeManager", "Failed to parse signed message: ${e.message}")
            null
        }
    }
    
    /**
     * Parse QR code content as public key data
     */
    fun parsePublicKeyData(qrContent: String): PublicKeyData? {
        return try {
            android.util.Log.d("QRCodeManager", "Starting public key data parsing")
            android.util.Log.d("QRCodeManager", "QR content length: ${qrContent.length}")
            android.util.Log.d("QRCodeManager", "QR content preview: ${qrContent.take(100)}${if (qrContent.length > 100) "..." else ""}")
            
            // 1. Type-specific input validation
            if (!isValidQRContent(qrContent, QRCodeType.PUBLIC_KEY)) {
                android.util.Log.w("QRCodeManager", "QR content validation failed for public key type")
                return null
            }
            
            // 2. JSON structure validation
            if (!isValidJsonWithRequiredFields(qrContent, listOf("publicKey", "contactName", "timestamp"))) {
                android.util.Log.w("QRCodeManager", "JSON structure validation failed")
                return null
            }
            
            // 3. Parse JSON
            android.util.Log.d("QRCodeManager", "Attempting JSON parsing")
            val result = gson.fromJson(qrContent, PublicKeyData::class.java)
            android.util.Log.d("QRCodeManager", "JSON parsing successful")
            
            // 4. Post-parse validation
            if (!isValidPublicKeyData(result)) {
                android.util.Log.w("QRCodeManager", "Public key data validation failed")
                return null
            }
            
            android.util.Log.d("QRCodeManager", "Public key data parsing completed successfully")
            result
        } catch (e: Exception) {
            android.util.Log.e("QRCodeManager", "Failed to parse public key data: ${e.message}", e)
            android.util.Log.e("QRCodeManager", "Exception type: ${e.javaClass.simpleName}")
            android.util.Log.e("QRCodeManager", "QR content that failed: ${qrContent}")
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

    /**
     * Detect the type of QR code content
     * 
     * @param qrContent The QR code content to analyze
     * @return QRCodeType indicating the content type
     */
    private fun detectQRContentType(qrContent: String): QRCodeType {
        return try {
            val jsonObject = gson.fromJson(qrContent, Map::class.java)
            when {
                jsonObject.containsKey("encryptedMessage") && jsonObject.containsKey("signature") -> QRCodeType.SIGNED_ENCRYPTED_MESSAGE
                jsonObject.containsKey("publicKey") && jsonObject.containsKey("contactName") -> QRCodeType.PUBLIC_KEY
                else -> QRCodeType.UNKNOWN
            }
        } catch (e: Exception) {
            QRCodeType.UNKNOWN
        }
    }

    /**
     * Validate QR code content for security and format
     * 
     * @param qrContent The QR code content to validate
     * @param expectedType Optional expected QR code type for more specific validation
     * @return true if content is valid, false otherwise
     */
    private fun isValidQRContent(qrContent: String, expectedType: QRCodeType? = null): Boolean {
        // 1. Basic length validation (allow single character messages)
        if (qrContent.isEmpty()) {
            android.util.Log.w("QRCodeManager", "QR content cannot be empty")
            return false
        }
        
        // 2. Determine content type and appropriate max length
        val contentType = expectedType ?: detectQRContentType(qrContent)
        val maxLength = when (contentType) {
            QRCodeType.SIGNED_ENCRYPTED_MESSAGE -> MAX_SIGNED_MESSAGE_QR_LENGTH
            QRCodeType.PUBLIC_KEY -> MAX_PUBLIC_KEY_QR_LENGTH
            QRCodeType.UNKNOWN -> MAX_PUBLIC_KEY_QR_LENGTH // Be permissive for unknown types
        }
        
        // 3. Maximum length validation (based on content type)
        if (qrContent.length > maxLength) {
            android.util.Log.w("QRCodeManager", "QR content too long: ${qrContent.length} (max: $maxLength for type: $contentType)")
            return false
        }
        
        // 4. Character encoding validation
        if (!qrContent.all { it.code in 32..126 || it.code in 160..255 || it.code in 0x2000..0x206F }) {
            android.util.Log.w("QRCodeManager", "QR content contains unsupported characters")
            return false
        }
        
        // 5. Malicious content detection
        val suspiciousPatterns = listOf(
            Regex("script", RegexOption.IGNORE_CASE),
            Regex("javascript:", RegexOption.IGNORE_CASE),
            Regex("data:", RegexOption.IGNORE_CASE),
            Regex("vbscript:", RegexOption.IGNORE_CASE),
            Regex("on\\w+\\s*=", RegexOption.IGNORE_CASE),
            Regex("<\\w+[^>]*>", RegexOption.IGNORE_CASE), // HTML tags
            Regex("\\b(union|select|insert|update|delete|drop|create|alter)\\b", RegexOption.IGNORE_CASE) // SQL keywords
        )
        
        if (suspiciousPatterns.any { it.containsMatchIn(qrContent) }) {
            android.util.Log.w("QRCodeManager", "QR content contains suspicious patterns")
            return false
        }
        
        android.util.Log.d("QRCodeManager", "QR content validation passed for type: $contentType")
        return true
    }
    
    /**
     * Validate JSON format and structure
     * 
     * @param content The content to validate as JSON
     * @param requiredFields List of required top-level fields
     * @return true if JSON is valid and contains required fields, false otherwise
     */
    private fun isValidJsonWithRequiredFields(content: String, requiredFields: List<String>): Boolean {
        return try {
            android.util.Log.d("QRCodeManager", "Validating JSON structure with required fields: $requiredFields")
            val jsonObject = gson.fromJson(content, Map::class.java)
            android.util.Log.d("QRCodeManager", "JSON parsed successfully, checking required fields")
            
            val missingFields = requiredFields.filter { !jsonObject.containsKey(it) }
            if (missingFields.isNotEmpty()) {
                android.util.Log.w("QRCodeManager", "Missing required fields: $missingFields")
                return false
            }
            
            android.util.Log.d("QRCodeManager", "All required fields present")
            true
        } catch (e: Exception) {
            android.util.Log.w("QRCodeManager", "Invalid JSON format: ${e.message}")
            false
        }
    }
    
    /**
     * Validate signed message structure and content
     * 
     * @param message The signed message to validate
     * @return true if message is valid, false otherwise
     */
    private fun isValidSignedMessage(message: CryptoManager.SignedEncryptedMessage?): Boolean {
        if (message == null) return false
        
        val encrypted = message.encryptedMessage
        
        // Validate all required fields individually
        if (encrypted.encryptedData.isEmpty()) {
            android.util.Log.w("QRCodeManager", "Signed message validation failed: encryptedData is empty")
            return false
        }
        
        if (encrypted.encryptedData.length > MAX_ENCRYPTED_FIELD_SIZE) {
            android.util.Log.w("QRCodeManager", "Signed message validation failed: encryptedData too large")
            return false
        }
        
        if (encrypted.encryptedKey.isEmpty()) {
            android.util.Log.w("QRCodeManager", "Signed message validation failed: encryptedKey is empty")
            return false
        }
        
        if (encrypted.encryptedKey.length > MAX_ENCRYPTED_FIELD_SIZE) {
            android.util.Log.w("QRCodeManager", "Signed message validation failed: encryptedKey too large")
            return false
        }
        
        if (encrypted.iv.isEmpty()) {
            android.util.Log.w("QRCodeManager", "Signed message validation failed: iv is empty")
            return false
        }
        
        if (encrypted.iv.length > MAX_IV_SIZE) {
            android.util.Log.w("QRCodeManager", "Signed message validation failed: iv too large")
            return false
        }
        
        if (encrypted.authTag.isEmpty()) {
            android.util.Log.w("QRCodeManager", "Signed message validation failed: authTag is empty")
            return false
        }
        
        if (encrypted.authTag.length > MAX_AUTH_TAG_SIZE) {
            android.util.Log.w("QRCodeManager", "Signed message validation failed: authTag too large")
            return false
        }
        
        if (encrypted.senderName.isEmpty()) {
            android.util.Log.w("QRCodeManager", "Signed message validation failed: senderName is empty")
            return false
        }
        
        if (encrypted.senderName.length > MAX_NAME_LENGTH) {
            android.util.Log.w("QRCodeManager", "Signed message validation failed: senderName too long")
            return false
        }
        
        if (encrypted.senderPublicKeyHash.isEmpty()) {
            android.util.Log.w("QRCodeManager", "Signed message validation failed: senderPublicKeyHash is empty")
            return false
        }
        
        if (encrypted.senderPublicKeyHash.length > MAX_HASH_SIZE) {
            android.util.Log.w("QRCodeManager", "Signed message validation failed: senderPublicKeyHash too large")
            return false
        }
        
        if (message.signature.isEmpty()) {
            android.util.Log.w("QRCodeManager", "Signed message validation failed: signature is empty")
            return false
        }
        
        if (message.signature.length > MAX_SIGNATURE_SIZE) {
            android.util.Log.w("QRCodeManager", "Signed message validation failed: signature too large")
            return false
        }
        
        if (encrypted.timestamp <= 0L) {
            android.util.Log.w("QRCodeManager", "Signed message validation failed: timestamp is invalid")
            return false
        }
        
        if (encrypted.timestamp > System.currentTimeMillis() + MAX_FUTURE_TIMESTAMP_MS) {
            android.util.Log.w("QRCodeManager", "Signed message validation failed: timestamp too far in future")
            return false
        }
        
        return true
    }
    
    /**
     * Validate public key data structure and content
     * 
     * @param data The public key data to validate
     * @return true if data is valid, false otherwise
     */
    private fun isValidPublicKeyData(data: PublicKeyData?): Boolean {
        if (data == null) return false
        
        // Validate all required fields individually
        if (data.publicKey.isEmpty()) {
            android.util.Log.w("QRCodeManager", "Public key data validation failed: publicKey is empty")
            return false
        }
        
        if (data.publicKey.length > MAX_ENCRYPTED_FIELD_SIZE) {
            android.util.Log.w("QRCodeManager", "Public key data validation failed: publicKey too large")
            return false
        }
        
        if (data.contactName.isEmpty()) {
            android.util.Log.w("QRCodeManager", "Public key data validation failed: contactName is empty")
            return false
        }
        
        if (data.contactName.length > MAX_NAME_LENGTH) {
            android.util.Log.w("QRCodeManager", "Public key data validation failed: contactName too long")
            return false
        }
        
        if (data.timestamp <= 0L) {
            android.util.Log.w("QRCodeManager", "Public key data validation failed: timestamp is invalid")
            return false
        }
        
        if (data.timestamp > System.currentTimeMillis() + MAX_FUTURE_TIMESTAMP_MS) {
            android.util.Log.w("QRCodeManager", "Public key data validation failed: timestamp too far in future")
            return false
        }
        
        return true
    }
} 