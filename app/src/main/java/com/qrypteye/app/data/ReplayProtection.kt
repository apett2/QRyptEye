package com.qrypteye.app.data

import android.util.Base64
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.concurrent.ConcurrentHashMap

/**
 * REPLAY PROTECTION SYSTEM
 * 
 * This class provides robust protection against replay attacks by tracking
 * previously seen messages and rejecting duplicates.
 * 
 * SECURITY FEATURES:
 * - Tracks message IDs to prevent exact duplicates
 * - Tracks message content hashes to prevent content-based replays
 * - Tracks session nonces to prevent nonce reuse attacks
 * - Uses secure hashing for message fingerprinting
 * - Thread-safe concurrent access
 * - Automatic cleanup of old entries
 * - Protection against memory exhaustion attacks
 */
class ReplayProtection {
    
    companion object {
        private const val MAX_TRACKED_MESSAGES = 10000 // Prevent memory exhaustion
        private const val CLEANUP_THRESHOLD = 8000 // Cleanup when reaching 80% capacity
        private const val MAX_MESSAGE_AGE_MS = 24 * 60 * 60 * 1000L // 24 hours
    }
    
    // Thread-safe storage for message tracking
    private val seenMessageIds = ConcurrentHashMap<String, Long>()
    private val seenMessageHashes = ConcurrentHashMap<String, Long>()
    private val seenSessionNonces = ConcurrentHashMap<String, Long>() // Track session nonces
    
    /**
     * Check if a message is a replay attack
     * 
     * @param message The message to check
     * @return true if this is a replay attack, false if it's a new message
     */
    fun isReplayAttack(message: SecureMessage): Boolean {
        // Check for exact message ID duplicate
        if (seenMessageIds.containsKey(message.id)) {
            return true
        }
        
        // Check for session nonce reuse (additional replay protection)
        if (seenSessionNonces.containsKey(message.sessionNonce)) {
            return true
        }
        
        // Check for content-based replay (same content, sender, timestamp)
        val contentHash = generateMessageHash(message)
        if (seenMessageHashes.containsKey(contentHash)) {
            return true
        }
        
        // Check if message is too old (replay protection)
        if (!message.isFresh()) {
            return true
        }
        
        // Add to tracking (if not at capacity)
        addToTracking(message, contentHash)
        
        return false
    }
    
    /**
     * Check if a message is a replay attack (for legacy Message objects)
     * 
     * @param message The message to check
     * @return true if this is a replay attack, false if it's a new message
     */
    fun isReplayAttack(message: Message): Boolean {
        // Check for exact message ID duplicate
        if (seenMessageIds.containsKey(message.id)) {
            return true
        }
        
        // Check for content-based replay (same content, sender, timestamp)
        val contentHash = generateMessageHash(message)
        if (seenMessageHashes.containsKey(contentHash)) {
            return true
        }
        
        // Check if message is too old (replay protection)
        val currentTime = System.currentTimeMillis()
        val maxAge = 24 * 60 * 60 * 1000L // 24 hours
        val maxFuture = 5 * 60 * 1000L // 5 minutes for clock skew
        
        if (currentTime - message.timestamp > maxAge) {
            return true
        }
        
        if (message.timestamp - currentTime > maxFuture) {
            return true
        }
        
        // Add to tracking (if not at capacity)
        addToTracking(message, contentHash)
        
        return false
    }
    
    /**
     * Generate a cryptographic hash of message content for replay detection
     * 
     * SECURITY: This method creates a canonical JSON representation of the message
     * for hash generation to ensure consistent replay detection.
     * 
     * CANONICAL PROPERTIES:
     * - Deterministic field ordering (alphabetical)
     * - Consistent null handling
     * - No HTML escaping
     * - Stable serialization format
     * 
     * HASHED FIELDS:
     * - id: Unique message identifier
     * - senderName: Name of the sender
     * - recipientName: Name of the recipient
     * - content: Message content
     * - timestamp: Message timestamp
     * - sessionNonce: Session nonce for additional replay protection
     * - isOutgoing: Message direction (immutable, safe to hash)
     * - hashContext: Additional context to prevent hash reuse
     * 
     * EXCLUDED FIELDS:
     * - isRead: Read status (mutable, user-specific, excluded from hash)
     *   This field is excluded to maintain hash consistency when marking messages as read.
     * 
     * @param message The message to hash
     * @return Base64-encoded hash of the message content
     */
    private fun generateMessageHash(message: SecureMessage): String {
        // Use the same canonical format as signature for consistency
        val messageContext = mapOf(
            "id" to message.id,
            "senderName" to message.senderName,
            "recipientName" to message.recipientName,
            "content" to message.content,
            "timestamp" to message.timestamp,
            "sessionNonce" to message.sessionNonce,
            "isOutgoing" to message.isOutgoing,
            "hashContext" to "QRyptEye-ReplayProtection-v3" // Updated version for isRead exclusion
        )
        
        // Use canonical Gson for deterministic JSON serialization
        val contentToHash = CanonicalGson.toJson(messageContext)
        return generateHash(contentToHash)
    }
    
    /**
     * Generate a cryptographic hash of message content for replay detection
     * 
     * SECURITY: This method creates a canonical JSON representation of the message
     * for hash generation to ensure consistent replay detection.
     * 
     * CANONICAL PROPERTIES:
     * - Deterministic field ordering (alphabetical)
     * - Consistent null handling
     * - No HTML escaping
     * - Stable serialization format
     * 
     * @param message The message to hash
     * @return Base64-encoded hash of the message content
     */
    private fun generateMessageHash(message: Message): String {
        // Use canonical JSON format for legacy messages too
        val messageContext = mapOf(
            "id" to message.id,
            "senderName" to message.senderName,
            "recipientName" to message.recipientName,
            "content" to message.content,
            "timestamp" to message.timestamp,
            "isOutgoing" to message.isOutgoing,
            "isRead" to message.isRead,
            "hashContext" to "QRyptEye-ReplayProtection-Legacy-v1" // Legacy context
        )
        
        // Use canonical Gson for deterministic JSON serialization
        val contentToHash = CanonicalGson.toJson(messageContext)
        return generateHash(contentToHash)
    }
    
    /**
     * Generate a secure hash of the given string
     * 
     * @param input The string to hash
     * @return Base64-encoded SHA-256 hash (URL-safe, no wrapping)
     */
    private fun generateHash(input: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val hashBytes = digest.digest(input.toByteArray())
        return Base64.encodeToString(hashBytes, Base64.NO_WRAP or Base64.URL_SAFE)
    }
    
    /**
     * Add message to tracking system
     * 
     * @param message The message to track
     * @param contentHash The hash of the message content
     */
    private fun addToTracking(message: SecureMessage, contentHash: String) {
        val currentTime = System.currentTimeMillis()
        
        // Check if we need to cleanup old entries
        if (seenMessageIds.size >= CLEANUP_THRESHOLD) {
            cleanupOldEntries(currentTime)
        }
        
        // Only add if we're not at capacity
        if (seenMessageIds.size < MAX_TRACKED_MESSAGES) {
            seenMessageIds[message.id] = currentTime
            seenMessageHashes[contentHash] = currentTime
            seenSessionNonces[message.sessionNonce] = currentTime
        }
    }
    
    /**
     * Add message to tracking system (for legacy Message objects)
     * 
     * @param message The message to track
     * @param contentHash The hash of the message content
     */
    private fun addToTracking(message: Message, contentHash: String) {
        val currentTime = System.currentTimeMillis()
        
        // Check if we need to cleanup old entries
        if (seenMessageIds.size >= CLEANUP_THRESHOLD) {
            cleanupOldEntries(currentTime)
        }
        
        // Only add if we're not at capacity
        if (seenMessageIds.size < MAX_TRACKED_MESSAGES) {
            seenMessageIds[message.id] = currentTime
            seenMessageHashes[contentHash] = currentTime
        }
    }
    
    /**
     * Clean up old entries to prevent memory exhaustion
     * 
     * @param currentTime Current timestamp
     */
    private fun cleanupOldEntries(currentTime: Long) {
        val cutoffTime = currentTime - MAX_MESSAGE_AGE_MS
        
        // Remove old message IDs
        seenMessageIds.entries.removeIf { entry ->
            entry.value < cutoffTime
        }
        
        // Remove old message hashes
        seenMessageHashes.entries.removeIf { entry ->
            entry.value < cutoffTime
        }

        // Remove old session nonces
        seenSessionNonces.entries.removeIf { entry ->
            entry.value < cutoffTime
        }
    }
    
    /**
     * Clear all tracked messages (for security purposes)
     */
    fun clearAll() {
        seenMessageIds.clear()
        seenMessageHashes.clear()
        seenSessionNonces.clear()
    }
    
    /**
     * Get statistics about tracked messages
     * 
     * @return Triple of (tracked message IDs count, tracked message hashes count, tracked session nonces count)
     */
    fun getStats(): Triple<Int, Int, Int> {
        return Triple(seenMessageIds.size, seenMessageHashes.size, seenSessionNonces.size)
    }
} 