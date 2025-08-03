package com.qrypteye.app.data

import java.security.SecureRandom
import java.util.*

data class Message(
    val id: String = generateSecureId(),
    val senderName: String,
    val recipientName: String,
    val content: String,
    val timestamp: Long = System.currentTimeMillis(),
    val isOutgoing: Boolean,
    val isRead: Boolean = false
) {
    companion object {
        private val secureRandom = SecureRandom()
        
        private fun generateSecureId(): String {
            val bytes = ByteArray(16)
            secureRandom.nextBytes(bytes)
            return android.util.Base64.encodeToString(bytes, android.util.Base64.URL_SAFE or android.util.Base64.NO_PADDING)
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
        return "Message(" +
                "id='$id', " +
                "senderName='[REDACTED]', " +
                "recipientName='[REDACTED]', " +
                "content='[REDACTED]', " +
                "timestamp=$timestamp, " +
                "isOutgoing=$isOutgoing, " +
                "isRead=$isRead" +
                ")"
    }
} 