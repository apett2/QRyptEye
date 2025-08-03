package com.qrypteye.app.data

import java.security.SecureRandom
import java.util.*
import android.util.Base64

/**
 * SECURE MESSAGE
 * 
 * This class represents a cryptographically signed message with integrity protection.
 * 
 * SECURITY FEATURES:
 * - Cryptographic signatures for authenticity verification
 * - Unique message IDs to prevent replay attacks
 * - Session nonces for additional replay protection
 * - Timestamp validation for freshness
 * - Sender verification through public key validation
 * - Tamper detection through signature verification
 */
data class SecureMessage(
    val id: String = generateSecureId(),
    val senderName: String,
    val recipientName: String,
    val content: String,
    val timestamp: Long = System.currentTimeMillis(),
    val sessionNonce: String = generateSessionNonce(), // Additional replay protection
    val isOutgoing: Boolean,
    val isRead: Boolean = false,
    val signature: String? = null,  // Cryptographic signature for authenticity
    val senderPublicKeyHash: String? = null  // Hash of sender's public key for verification
) {
    companion object {
        private val secureRandom = SecureRandom()
        
        private fun generateSecureId(): String {
            val bytes = ByteArray(16)
            secureRandom.nextBytes(bytes)
            return Base64.encodeToString(bytes, Base64.URL_SAFE or Base64.NO_PADDING)
        }
        
        private fun generateSessionNonce(): String {
            val bytes = ByteArray(12) // 96-bit nonce for additional security
            secureRandom.nextBytes(bytes)
            return Base64.encodeToString(bytes, Base64.URL_SAFE or Base64.NO_PADDING)
        }
        
        /**
         * Create a SecureMessage for signing (excludes mutable fields)
         * 
         * SECURITY: This method creates a message with default isRead=false
         * for cryptographic signing. The isRead field is excluded from signing
         * to allow legitimate local updates without breaking signature integrity.
         * 
         * @param senderName Name of the sender
         * @param recipientName Name of the recipient
         * @param content Message content
         * @param isOutgoing Whether this is an outgoing message
         * @return SecureMessage ready for signing
         */
        fun createForSigning(
            senderName: String,
            recipientName: String,
            content: String,
            isOutgoing: Boolean
        ): SecureMessage {
            return SecureMessage(
                senderName = senderName,
                recipientName = recipientName,
                content = content,
                isOutgoing = isOutgoing,
                isRead = false // Default value, excluded from signature
            )
        }
    }
    
    /**
     * Create a message data string for signing
     * 
     * SECURITY: This creates a canonical JSON representation of the message
     * for cryptographic signing to prevent tampering and ensure unambiguous parsing.
     * 
     * CANONICAL PROPERTIES:
     * - Deterministic field ordering (alphabetical)
     * - Consistent null handling
     * - No HTML escaping
     * - Stable serialization format
     * 
     * SIGNED FIELDS:
     * - id: Unique message identifier
     * - senderName: Name of the sender
     * - recipientName: Name of the recipient  
     * - content: Message content
     * - timestamp: Message timestamp
     * - sessionNonce: Session nonce for additional replay protection
     * - isOutgoing: Message direction (immutable, safe to sign)
     * - signatureContext: Additional context to prevent signature reuse
     * 
     * EXCLUDED FIELDS:
     * - isRead: Read status (mutable, user-specific, stored separately)
     *   This field is excluded from signing to allow legitimate local updates
     *   without breaking cryptographic integrity.
     */
    fun createMessageData(): String {
        val messageContext = mapOf(
            "id" to id,
            "senderName" to senderName,
            "recipientName" to recipientName,
            "content" to content,
            "timestamp" to timestamp,
            "sessionNonce" to sessionNonce,
            "isOutgoing" to isOutgoing,
            "signatureContext" to "QRyptEye-SecureMessage-v3" // Updated version for isRead exclusion
        )
        
        // Use canonical Gson for deterministic JSON serialization
        return CanonicalGson.toJson(messageContext)
    }
    
    /**
     * Verify if this message is authentic
     * 
     * @param senderPublicKey The public key of the claimed sender
     * @return true if the message signature is valid, false otherwise
     */
    fun isAuthentic(senderPublicKey: java.security.PublicKey): Boolean {
        if (signature == null) return false
        
        try {
            val cryptoManager = com.qrypteye.app.crypto.CryptoManager()
            val messageData = createMessageData()
            return cryptoManager.verifySignature(messageData, signature, senderPublicKey)
        } catch (e: Exception) {
            return false
        }
    }
    
    /**
     * Check if this message is fresh (not a replay attack)
     * 
     * @param maxAgeMs Maximum age in milliseconds (default: 24 hours)
     * @param maxFutureMs Maximum future time in milliseconds (default: 5 minutes)
     * @return true if the message is fresh, false otherwise
     */
    fun isFresh(maxAgeMs: Long = 24 * 60 * 60 * 1000L, maxFutureMs: Long = 5 * 60 * 1000L): Boolean {
        val currentTime = System.currentTimeMillis()
        
        // Check if message is too old
        if (currentTime - timestamp > maxAgeMs) {
            return false
        }
        
        // Check if message is from the future (clock skew)
        if (timestamp - currentTime > maxFutureMs) {
            return false
        }
        
        return true
    }
    
    /**
     * Create a signed version of this message
     * 
     * @param senderPrivateKey The private key of the sender
     * @param senderPublicKey The public key of the sender (for hash generation)
     * @return A new SecureMessage with cryptographic signature
     */
    fun sign(senderPrivateKey: java.security.PrivateKey, senderPublicKey: java.security.PublicKey): SecureMessage {
        try {
            val cryptoManager = com.qrypteye.app.crypto.CryptoManager()
            val messageData = createMessageData()
            val signature = cryptoManager.signData(messageData, senderPrivateKey)
            
            // Create hash of sender's public key for verification
            // SECURITY: Uses URL_SAFE and NO_WRAP flags to prevent newline artifacts
            val senderPublicKeyHash = java.security.MessageDigest.getInstance("SHA-256")
                .digest(senderPublicKey.encoded)
                .let { Base64.encodeToString(it, Base64.URL_SAFE or Base64.NO_WRAP) }
            
            return this.copy(
                signature = signature,
                senderPublicKeyHash = senderPublicKeyHash
            )
        } catch (e: Exception) {
            throw SecurityException("Failed to sign message", e)
        }
    }

    /**
     * Secure toString() implementation that prevents accidental exposure of sensitive data
     * 
     * SECURITY: This method ensures that sensitive fields like content, senderName, and recipientName
     * are never exposed in string representations, preventing accidental logging of sensitive data.
     * 
     * @return A safe string representation containing only non-sensitive fields
     */
    override fun toString(): String {
        return "SecureMessage(" +
                "id='$id', " +
                "senderName='[REDACTED]', " +
                "recipientName='[REDACTED]', " +
                "content='[REDACTED]', " +
                "timestamp=$timestamp, " +
                "sessionNonce='$sessionNonce', " +
                "isOutgoing=$isOutgoing, " +
                "isRead=$isRead, " +
                "signature=${if (signature != null) "[PRESENT]" else "null"}, " +
                "senderPublicKeyHash=${if (senderPublicKeyHash != null) "[PRESENT]" else "null"}" +
                ")"
    }
} 