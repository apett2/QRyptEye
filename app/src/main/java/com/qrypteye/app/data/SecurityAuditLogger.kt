package com.qrypteye.app.data

import android.util.Log
import java.security.MessageDigest
import android.util.Base64

/**
 * SECURITY AUDIT LOGGER
 * 
 * This class provides secure logging and auditing of cryptographic operations
 * without exposing sensitive data like private keys or message content.
 * 
 * SECURITY FEATURES:
 * - Logs cryptographic events without sensitive data
 * - Provides audit trail for security analysis
 * - Uses secure hashing for message identification
 * - Categorizes different types of security events
 * - Enables user feedback for security issues
 * - Prevents information disclosure through logs
 */

// Event types for categorization
enum class SecurityEvent {
    MESSAGE_VERIFIED,
    MESSAGE_VERIFICATION_FAILED,
    REPLAY_ATTACK_DETECTED,
    TIMESTAMP_REGRESSION_DETECTED,
    SIGNATURE_INVALID,
    DATA_INTEGRITY_VIOLATION,  // For replay/substitution attack detection
    METADATA_SIGNATURE_VIOLATION,  // New: For metadata tampering detection
    KEY_ROTATION,
    KEY_GENERATION,
    KEY_IMPORT,
    KEY_EXPORT,
    ENCRYPTION_SUCCESS,
    ENCRYPTION_FAILED,
    DECRYPTION_SUCCESS,
    DECRYPTION_FAILED,
    CLOCK_DRIFT_DETECTED,
    MEMORY_EXHAUSTION_PREVENTED
}

class SecurityAuditLogger {
    
    companion object {
        private const val TAG = "QRyptEye-Security"
        private const val MAX_LOG_ENTRIES = 1000 // Prevent log exhaustion
    }
    
    // Thread-safe storage for recent audit events
    private val recentEvents = mutableListOf<AuditEvent>()
    
    /**
     * Log a security event with appropriate detail level
     * 
     * @param eventType The type of security event
     * @param details Additional details (no sensitive data)
     * @param messageHash Optional hash of message for identification
     * @param senderHash Optional hash of sender for identification
     */
    fun logSecurityEvent(
        eventType: SecurityEvent,
        details: String = "",
        messageHash: String? = null,
        senderHash: String? = null
    ) {
        val auditEvent = AuditEvent(
            timestamp = System.currentTimeMillis(),
            eventType = eventType,
            details = details,
            messageHash = messageHash,
            senderHash = senderHash
        )
        
        // Add to recent events (with size limit)
        synchronized(recentEvents) {
            if (recentEvents.size >= MAX_LOG_ENTRIES) {
                recentEvents.removeAt(0) // Remove oldest entry
            }
            recentEvents.add(auditEvent)
        }
        
        // Log to Android logcat (for debugging)
        val logMessage = buildLogMessage(auditEvent)
        when (eventType) {
            SecurityEvent.MESSAGE_VERIFIED,
            SecurityEvent.ENCRYPTION_SUCCESS,
            SecurityEvent.DECRYPTION_SUCCESS,
            SecurityEvent.KEY_GENERATION,
            SecurityEvent.KEY_IMPORT -> {
                Log.i(TAG, logMessage)
            }
            SecurityEvent.MESSAGE_VERIFICATION_FAILED,
            SecurityEvent.ENCRYPTION_FAILED,
            SecurityEvent.DECRYPTION_FAILED -> {
                Log.w(TAG, logMessage)
            }
            SecurityEvent.REPLAY_ATTACK_DETECTED,
            SecurityEvent.TIMESTAMP_REGRESSION_DETECTED,
            SecurityEvent.SIGNATURE_INVALID,
            SecurityEvent.DATA_INTEGRITY_VIOLATION,
            SecurityEvent.METADATA_SIGNATURE_VIOLATION -> {
                Log.e(TAG, logMessage)
            }
            else -> {
                Log.d(TAG, logMessage)
            }
        }
    }
    
    /**
     * Generate a hash of message content for audit logging
     * 
     * SECURITY: Uses URL_SAFE and NO_WRAP flags to prevent newline artifacts
     * and ensure cross-platform compatibility.
     * 
     * @param messageContent The message content to hash
     * @return Base64-encoded hash of the message content
     */
    fun generateMessageHash(messageContent: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val hashBytes = digest.digest(messageContent.toByteArray())
        return Base64.encodeToString(hashBytes, Base64.URL_SAFE or Base64.NO_WRAP)
    }
    
    /**
     * Generate a secure hash of sender information for logging
     * 
     * SECURITY: Uses URL_SAFE and NO_WRAP flags to prevent newline artifacts
     * and ensure cross-platform compatibility.
     * 
     * @param senderName The sender name to hash
     * @return Base64-encoded hash of the sender name
     */
    fun generateSenderHash(senderName: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val hashBytes = digest.digest(senderName.toByteArray())
        return Base64.encodeToString(hashBytes, Base64.URL_SAFE or Base64.NO_WRAP)
    }
    
    /**
     * Get recent security events for user feedback
     * 
     * @param maxEvents Maximum number of events to return
     * @return List of recent audit events
     */
    fun getRecentEvents(maxEvents: Int = 50): List<AuditEvent> {
        synchronized(recentEvents) {
            return recentEvents.takeLast(maxEvents)
        }
    }
    
    /**
     * Get security statistics for user feedback
     * 
     * @return SecurityStatistics object with counts
     */
    fun getSecurityStatistics(): SecurityStatistics {
        synchronized(recentEvents) {
            val stats = SecurityStatistics()
            recentEvents.forEach { event ->
                when (event.eventType) {
                    SecurityEvent.MESSAGE_VERIFIED -> stats.messagesVerified++
                    SecurityEvent.MESSAGE_VERIFICATION_FAILED -> stats.messagesVerificationFailed++
                    SecurityEvent.REPLAY_ATTACK_DETECTED -> stats.replayAttacksDetected++
                    SecurityEvent.TIMESTAMP_REGRESSION_DETECTED -> stats.timestampRegressionsDetected++
                    SecurityEvent.SIGNATURE_INVALID -> stats.invalidSignatures++
                    SecurityEvent.KEY_ROTATION -> stats.keyRotations++
                    SecurityEvent.KEY_GENERATION -> stats.keyGenerations++
                    else -> { /* Count other events as needed */ }
                }
            }
            return stats
        }
    }
    
    /**
     * Clear all audit events (for security purposes)
     */
    fun clearAll() {
        synchronized(recentEvents) {
            recentEvents.clear()
        }
    }
    
    /**
     * Build a log message from an audit event
     * 
     * @param event The audit event
     * @return Formatted log message
     */
    private fun buildLogMessage(event: AuditEvent): String {
        val baseMessage = "[${event.eventType}] ${event.details}"
        val hashInfo = buildString {
            if (event.messageHash != null) {
                append(" MessageHash: ${event.messageHash.take(8)}...")
            }
            if (event.senderHash != null) {
                append(" SenderHash: ${event.senderHash.take(8)}...")
            }
        }
        return baseMessage + hashInfo
    }
    
    /**
     * Data class for audit events
     */
    data class AuditEvent(
        val timestamp: Long,
        val eventType: SecurityEvent,
        val details: String,
        val messageHash: String?,
        val senderHash: String?
    )
    
    /**
     * Data class for security statistics
     */
    data class SecurityStatistics(
        var messagesVerified: Int = 0,
        var messagesVerificationFailed: Int = 0,
        var replayAttacksDetected: Int = 0,
        var timestampRegressionsDetected: Int = 0,
        var invalidSignatures: Int = 0,
        var keyRotations: Int = 0,
        var keyGenerations: Int = 0
    )
} 