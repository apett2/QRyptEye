package com.qrypteye.app.data

import android.util.Base64
import java.security.MessageDigest
import java.util.concurrent.ConcurrentHashMap

/**
 * SENDER TIMESTAMP TRACKER
 * 
 * This class tracks the latest timestamp and recent message IDs received from each sender
 * to prevent both timestamp regression attacks and message replay attacks.
 * 
 * SECURITY FEATURES:
 * - Tracks latest timestamp per sender (prevents timestamp regression)
 * - Tracks recent message IDs per sender (prevents message replay)
 * - Uses sender public key hash for identification
 * - Supports key rotation by tracking multiple keys per contact
 * - Thread-safe concurrent access
 * - Automatic cleanup of old entries
 * - Protection against memory exhaustion
 * - Sliding window for recent message tracking
 * 
 * KEY ROTATION SUPPORT:
 * - Tracks multiple public keys per contact to support key rotation
 * - Maintains replay protection continuity across key changes
 * - Prevents replay attacks even when contacts rotate their keys
 * - Supports both single-key and multi-key contact scenarios
 */
class SenderTimestampTracker {
    
    companion object {
        private const val MAX_TRACKED_SENDERS = 1000 // Prevent memory exhaustion
        private const val CLEANUP_THRESHOLD = 800 // Cleanup when reaching 80% capacity
        private const val MAX_SENDER_AGE_MS = 7 * 24 * 60 * 60 * 1000L // 7 days
        private const val ALLOWED_CLOCK_DRIFT_MS = 2 * 60 * 1000L // 2 minutes
        
        // Message replay protection constants
        private const val MAX_RECENT_MESSAGES_PER_SENDER = 10 // Track last 10 messages per sender
        private const val MESSAGE_ID_WINDOW_MS = 5 * 60 * 1000L // 5 minutes for message ID tracking
        
        // Key rotation support constants
        private const val MAX_KEYS_PER_CONTACT = 5 // Track up to 5 keys per contact
        private const val KEY_ROTATION_WINDOW_MS = 30 * 24 * 60 * 60 * 1000L // 30 days for key rotation
    }
    
    // Thread-safe storage for sender timestamp tracking (by contact ID)
    private val contactTimestamps = ConcurrentHashMap<String, Long>()
    
    // Thread-safe storage for recent message IDs per contact (by contact ID)
    private val contactRecentMessages = ConcurrentHashMap<String, MutableSet<String>>()
    
    // Thread-safe storage for message timestamps (for cleanup)
    private val messageTimestamps = ConcurrentHashMap<String, Long>()
    
    // Thread-safe storage for public key to contact ID mapping
    private val keyToContactMapping = ConcurrentHashMap<String, String>()
    
    // Thread-safe storage for contact ID to public key hashes mapping
    private val contactToKeysMapping = ConcurrentHashMap<String, MutableSet<String>>()
    
    // Thread-safe storage for key timestamps (for cleanup)
    private val keyTimestamps = ConcurrentHashMap<String, Long>()
    
    // Reference to the main replay protection system
    private val replayProtection = ReplayProtection()
    
    /**
     * Validate timestamp and message ID for a sender and update tracking
     * 
     * SECURITY: This method provides comprehensive replay protection by:
     * 1. Checking for timestamp regression (prevents old message replay)
     * 2. Checking for message ID reuse (prevents exact message replay)
     * 3. Validating clock drift (prevents future message attacks)
     * 4. Supporting key rotation (maintains replay protection across key changes)
     * 5. Using consolidated replay protection system
     * 
     * @param senderPublicKey The sender's public key
     * @param messageId The unique message identifier
     * @param messageTimestamp The timestamp of the message
     * @param contactId The contact ID (optional, for key rotation support)
     * @return true if message is valid, false if it's a replay attack
     */
    fun validateAndUpdateMessage(
        senderPublicKey: java.security.PublicKey, 
        messageId: String, 
        messageTimestamp: Long,
        contactId: String? = null
    ): Boolean {
        val senderHash = generateSenderHash(senderPublicKey)
        val currentTime = System.currentTimeMillis()
        
        // Determine the contact ID for tracking
        val trackingContactId = contactId ?: senderHash // Fallback to hash if no contact ID
        
        // Update key-to-contact mapping for key rotation support
        updateKeyMapping(senderHash, trackingContactId, currentTime)
        
        // SECURITY: Use consolidated replay protection for message ID validation
        val tempMessage = com.qrypteye.app.data.Message(
            id = messageId,
            senderName = "temp_sender",
            recipientName = "temp_recipient",
            content = "temp_content",
            timestamp = messageTimestamp,
            isOutgoing = false,
            isRead = false
        )
        
        if (replayProtection.isReplayAttack(tempMessage)) {
            android.util.Log.w("SenderTimestampTracker", "Replay attack detected via consolidated system")
            return false
        }
        
        // Check for timestamp regression (per contact, not per key)
        val lastTimestamp = contactTimestamps[trackingContactId]
        if (lastTimestamp != null && messageTimestamp <= lastTimestamp) {
            android.util.Log.w("SenderTimestampTracker", "Timestamp regression detected")
            return false // Timestamp regression detected
        }
        
        // Check for excessive clock drift
        if (Math.abs(messageTimestamp - currentTime) > ALLOWED_CLOCK_DRIFT_MS) {
            android.util.Log.w("SenderTimestampTracker", "Excessive clock drift detected")
            return false // Clock drift too large
        }
        
        // Check if we need to cleanup old entries
        if (contactTimestamps.size >= CLEANUP_THRESHOLD) {
            cleanupOldEntries(currentTime)
        }
        
        // Only update if we're not at capacity
        if (contactTimestamps.size < MAX_TRACKED_SENDERS) {
            // Update timestamp tracking (per contact)
            contactTimestamps[trackingContactId] = messageTimestamp
            
            // Update message ID tracking (per contact)
            val recentMessages = contactRecentMessages.getOrPut(trackingContactId) { mutableSetOf() }
            synchronized(recentMessages) {
                // Add new message ID
                recentMessages.add(messageId)
                messageTimestamps[messageId] = currentTime
                
                // Maintain sliding window size
                if (recentMessages.size > MAX_RECENT_MESSAGES_PER_SENDER) {
                    // Remove oldest message IDs (this is approximate but sufficient for security)
                    val oldestMessages = recentMessages.take(recentMessages.size - MAX_RECENT_MESSAGES_PER_SENDER)
                    recentMessages.removeAll(oldestMessages)
                    oldestMessages.forEach { messageTimestamps.remove(it) }
                }
            }
        }
        
        return true
    }
    
    /**
     * Update key-to-contact mapping for key rotation support
     * 
     * SECURITY: This method maintains the mapping between public key hashes and contact IDs
     * to support key rotation while maintaining replay protection continuity.
     * 
     * @param senderHash The hash of the sender's public key
     * @param contactId The contact ID for tracking
     * @param currentTime Current timestamp
     */
    private fun updateKeyMapping(senderHash: String, contactId: String, currentTime: Long) {
        // Update key-to-contact mapping
        keyToContactMapping[senderHash] = contactId
        
        // Update contact-to-keys mapping
        val contactKeys = contactToKeysMapping.getOrPut(contactId) { mutableSetOf() }
        synchronized(contactKeys) {
            contactKeys.add(senderHash)
            keyTimestamps[senderHash] = currentTime
            
            // Maintain maximum keys per contact
            if (contactKeys.size > MAX_KEYS_PER_CONTACT) {
                // Remove oldest keys (approximate but sufficient for security)
                val oldestKeys = contactKeys.take(contactKeys.size - MAX_KEYS_PER_CONTACT)
                contactKeys.removeAll(oldestKeys)
                oldestKeys.forEach { 
                    keyTimestamps.remove(it)
                    keyToContactMapping.remove(it)
                }
            }
        }
    }
    
    /**
     * Validate timestamp for a sender and update tracking (legacy method for backward compatibility)
     * 
     * @deprecated Use validateAndUpdateMessage() for comprehensive replay protection
     * @param senderPublicKey The sender's public key
     * @param messageTimestamp The timestamp of the message
     * @return true if timestamp is valid, false if it's a regression attack
     */
    @Deprecated("Use validateAndUpdateMessage() for comprehensive replay protection")
    fun validateAndUpdateTimestamp(senderPublicKey: java.security.PublicKey, messageTimestamp: Long): Boolean {
        // Create a temporary message ID for timestamp-only validation
        val tempMessageId = "timestamp_only_${messageTimestamp}_${System.currentTimeMillis()}"
        return validateAndUpdateMessage(senderPublicKey, tempMessageId, messageTimestamp)
    }
    
    /**
     * Generate a hash of the sender's public key for tracking
     * 
     * SECURITY: Uses URL_SAFE and NO_WRAP flags to prevent newline artifacts
     * and ensure cross-platform compatibility.
     * 
     * @param senderPublicKey The sender's public key
     * @return Base64-encoded hash of the public key
     */
    private fun generateSenderHash(senderPublicKey: java.security.PublicKey): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val hashBytes = digest.digest(senderPublicKey.encoded)
        return Base64.encodeToString(hashBytes, Base64.URL_SAFE or Base64.NO_WRAP)
    }
    
    /**
     * Clean up old entries to prevent memory exhaustion
     * 
     * SECURITY: Removes old timestamp, message ID, and key mapping entries to prevent
     * memory exhaustion attacks while maintaining recent replay protection.
     * 
     * @param currentTime Current timestamp
     */
    private fun cleanupOldEntries(currentTime: Long) {
        val cutoffTime = currentTime - MAX_SENDER_AGE_MS
        val messageCutoffTime = currentTime - MESSAGE_ID_WINDOW_MS
        val keyCutoffTime = currentTime - KEY_ROTATION_WINDOW_MS
        
        // Remove old contact timestamp entries
        contactTimestamps.entries.removeIf { entry ->
            entry.value < cutoffTime
        }
        
        // Remove old message ID entries
        messageTimestamps.entries.removeIf { entry ->
            entry.value < messageCutoffTime
        }
        
        // Remove old key mapping entries
        keyTimestamps.entries.removeIf { entry ->
            entry.value < keyCutoffTime
        }
        
        // Clean up message ID sets for contacts that are no longer tracked
        contactRecentMessages.entries.removeIf { entry ->
            !contactTimestamps.containsKey(entry.key)
        }
        
        // Clean up key mappings for keys that are no longer tracked
        keyToContactMapping.entries.removeIf { entry ->
            !keyTimestamps.containsKey(entry.key)
        }
        
        // Clean up contact-to-keys mappings for contacts that are no longer tracked
        contactToKeysMapping.entries.removeIf { entry ->
            !contactTimestamps.containsKey(entry.key)
        }
    }
    
    /**
     * Clear all tracked data (for security purposes)
     */
    fun clearAll() {
        contactTimestamps.clear()
        contactRecentMessages.clear()
        messageTimestamps.clear()
        keyToContactMapping.clear()
        contactToKeysMapping.clear()
        keyTimestamps.clear()
    }
    
    /**
     * Get statistics about tracked senders
     * 
     * @return Quintuple of (tracked contacts count, total tracked messages, total message timestamps, total tracked keys, total key mappings)
     */
    fun getStats(): Quintuple<Int, Int, Int, Int, Int> {
        val totalMessages = contactRecentMessages.values.sumOf { it.size }
        val totalKeys = keyToContactMapping.size
        val totalKeyMappings = contactToKeysMapping.values.sumOf { it.size }
        return Quintuple(contactTimestamps.size, totalMessages, messageTimestamps.size, totalKeys, totalKeyMappings)
    }
    
    /**
     * Get the latest timestamp for a specific sender
     * 
     * @param senderPublicKey The sender's public key
     * @return The latest timestamp, or null if not tracked
     */
    fun getLatestTimestamp(senderPublicKey: java.security.PublicKey): Long? {
        val senderHash = generateSenderHash(senderPublicKey)
        val contactId = keyToContactMapping[senderHash] ?: senderHash
        return contactTimestamps[contactId]
    }
    
    /**
     * Get recent message IDs for a specific sender
     * 
     * @param senderPublicKey The sender's public key
     * @return Set of recent message IDs, or empty set if not tracked
     */
    fun getRecentMessageIds(senderPublicKey: java.security.PublicKey): Set<String> {
        val senderHash = generateSenderHash(senderPublicKey)
        val contactId = keyToContactMapping[senderHash] ?: senderHash
        return contactRecentMessages[contactId]?.toSet() ?: emptySet()
    }
    
    /**
     * Check if a specific message ID has been seen for a sender
     * 
     * @param senderPublicKey The sender's public key
     * @param messageId The message ID to check
     * @return true if the message ID has been seen, false otherwise
     */
    fun hasSeenMessage(senderPublicKey: java.security.PublicKey, messageId: String): Boolean {
        val senderHash = generateSenderHash(senderPublicKey)
        val contactId = keyToContactMapping[senderHash] ?: senderHash
        val recentMessages = contactRecentMessages[contactId]
        return recentMessages?.contains(messageId) == true
    }
    
    /**
     * Get all public key hashes associated with a contact
     * 
     * @param contactId The contact ID
     * @return Set of public key hashes, or empty set if not tracked
     */
    fun getContactKeys(contactId: String): Set<String> {
        return contactToKeysMapping[contactId]?.toSet() ?: emptySet()
    }
    
    /**
     * Get the contact ID associated with a public key
     * 
     * @param senderPublicKey The sender's public key
     * @return The contact ID, or null if not tracked
     */
    fun getContactId(senderPublicKey: java.security.PublicKey): String? {
        val senderHash = generateSenderHash(senderPublicKey)
        return keyToContactMapping[senderHash]
    }
    
    /**
     * Remove a specific key from tracking (for key rotation cleanup)
     * 
     * @param senderPublicKey The public key to remove
     */
    fun removeKey(senderPublicKey: java.security.PublicKey) {
        val senderHash = generateSenderHash(senderPublicKey)
        val contactId = keyToContactMapping[senderHash]
        
        if (contactId != null) {
            // Remove from contact-to-keys mapping
            contactToKeysMapping[contactId]?.remove(senderHash)
            
            // Clean up empty contact mappings
            if (contactToKeysMapping[contactId]?.isEmpty() == true) {
                contactToKeysMapping.remove(contactId)
            }
        }
        
        // Remove from key mappings
        keyToContactMapping.remove(senderHash)
        keyTimestamps.remove(senderHash)
    }
    
    /**
     * Remove all keys for a specific contact (for contact deletion)
     * 
     * @param contactId The contact ID to remove
     */
    fun removeContact(contactId: String) {
        // Get all keys for this contact
        val keys = contactToKeysMapping[contactId]?.toSet() ?: emptySet()
        
        // Remove all keys
        keys.forEach { keyHash ->
            keyToContactMapping.remove(keyHash)
            keyTimestamps.remove(keyHash)
        }
        
        // Remove contact mappings
        contactToKeysMapping.remove(contactId)
        contactTimestamps.remove(contactId)
        contactRecentMessages.remove(contactId)
    }
}

/**
 * Simple data class for returning quintuple statistics
 */
data class Quintuple<A, B, C, D, E>(
    val first: A,
    val second: B,
    val third: C,
    val fourth: D,
    val fifth: E
) 