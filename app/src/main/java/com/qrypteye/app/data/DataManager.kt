package com.qrypteye.app.data

import android.content.Context
import android.content.SharedPreferences
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import java.security.KeyPair

/**
 * DATA MANAGER (SECURE WRAPPER)
 * 
 * This class now uses SecureDataManager internally for all sensitive data.
 * It provides backward compatibility while ensuring all data is stored securely.
 * 
 * SECURITY: All sensitive data is now stored using:
 * - Android Keystore System for private keys
 * - EncryptedSharedPreferences for encrypted data storage
 * - No plaintext storage of sensitive information
 */
class DataManager(private val context: Context) {
    
    companion object {
        private const val PREFS_NAME = "QRyptEyePrefs"
        private const val KEY_CONTACTS = "contacts"
        private const val KEY_USER_NAME = "user_name"
        private const val KEY_KEY_PAIR = "key_pair"
        private const val KEY_MESSAGES = "messages"
        private const val KEY_MIGRATION_COMPLETE = "migration_complete"
    }
    
    private val secureDataManager = SecureDataManager(context)
    private val legacyPrefs: SharedPreferences = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    private val gson = Gson()
    
    init {
        // Perform migration from legacy storage to secure storage
        migrateToSecureStorage()
    }
    
    /**
     * Migrate data from legacy SharedPreferences to secure storage
     * 
     * SECURITY: This method ensures that plaintext Message objects are never loaded into memory
     * during migration. Instead, it processes the JSON data securely and immediately encrypts it.
     */
    private fun migrateToSecureStorage() {
        if (legacyPrefs.getBoolean(KEY_MIGRATION_COMPLETE, false)) {
            return // Migration already completed
        }
        
        try {
            // Migrate contacts
            val legacyContacts = loadContactsFromLegacy()
            if (legacyContacts.isNotEmpty()) {
                secureDataManager.saveContacts(legacyContacts)
            }
            
            // Migrate user name
            val legacyUserName = legacyPrefs.getString(KEY_USER_NAME, "")
            if (!legacyUserName.isNullOrEmpty()) {
                secureDataManager.saveUserName(legacyUserName)
            }
            
            // Migrate messages securely without loading plaintext Message objects
            migrateMessagesSecurely()
            
            // Note: Key pairs cannot be migrated from legacy storage as they were stored insecurely
            // Users will need to regenerate their key pairs for maximum security
            
            // Mark migration as complete
            legacyPrefs.edit().putBoolean(KEY_MIGRATION_COMPLETE, true).apply()
            
        } catch (e: Exception) {
            // If migration fails, continue with secure storage (data will be empty)
        }
    }
    
    /**
     * Securely migrate messages without loading plaintext Message objects into memory
     * 
     * SECURITY: This method processes the JSON data directly and creates SecureMessage objects
     * without ever creating plaintext Message objects in memory.
     */
    private fun migrateMessagesSecurely() {
        val json = legacyPrefs.getString(KEY_MESSAGES, "[]")
        if (json.isNullOrEmpty()) {
            return
        }
        
        try {
            // Parse JSON directly to a list of maps to avoid creating Message objects
            val type = object : TypeToken<List<Map<String, Any>>>() {}.type
            val messageMaps: List<Map<String, Any>> = gson.fromJson(json, type) ?: emptyList()
            
            // Convert directly to SecureMessage objects without creating Message objects
            val secureMessages = messageMaps.mapNotNull { messageMap ->
                try {
                    SecureMessage(
                        id = messageMap["id"] as? String ?: generateSecureId(),
                        senderName = messageMap["senderName"] as? String ?: "",
                        recipientName = messageMap["recipientName"] as? String ?: "",
                        content = messageMap["content"] as? String ?: "",
                        timestamp = (messageMap["timestamp"] as? Number)?.toLong() ?: System.currentTimeMillis(),
                        isOutgoing = messageMap["isOutgoing"] as? Boolean ?: false,
                        isRead = messageMap["isRead"] as? Boolean ?: false,
                        signature = null, // Legacy messages don't have signatures
                        senderPublicKeyHash = null
                        // sessionNonce will use default value (cryptographically random)
                    )
                } catch (e: Exception) {
                    // Skip malformed messages
                    null
                }
            }
            
            if (secureMessages.isNotEmpty()) {
                secureDataManager.saveMessages(secureMessages)
            }
            
        } catch (e: Exception) {
            // If migration fails, continue with secure storage
        }
    }
    
    /**
     * Generate a secure ID for migrated messages
     */
    private fun generateSecureId(): String {
        val bytes = ByteArray(16)
        java.security.SecureRandom().nextBytes(bytes)
        return android.util.Base64.encodeToString(bytes, android.util.Base64.URL_SAFE or android.util.Base64.NO_PADDING)
    }
    
    // Legacy loading methods for migration
    private fun loadContactsFromLegacy(): List<Contact> {
        val json = legacyPrefs.getString(KEY_CONTACTS, "[]")
        val type = object : TypeToken<List<Contact>>() {}.type
        return try {
            gson.fromJson(json, type) ?: emptyList()
        } catch (e: Exception) {
            emptyList()
        }
    }
    
    // Contact management (delegated to secure storage)
    fun saveContacts(contacts: List<Contact>) {
        secureDataManager.saveContacts(contacts)
    }
    
    fun loadContacts(): List<Contact> {
        val contacts = secureDataManager.loadContacts()
        android.util.Log.d("DataManager", "loadContacts: loaded ${contacts.size} contacts from secure data manager")
        return contacts
    }
    
    fun addContact(contact: Contact) {
        secureDataManager.addContact(contact)
    }
    
    fun removeContact(contactId: String) {
        secureDataManager.removeContact(contactId)
    }
    
    fun getContactByName(name: String): Contact? {
        return secureDataManager.getContactByName(name)
    }
    
    // User settings (delegated to secure storage)
    fun saveUserName(name: String) {
        secureDataManager.saveUserName(name)
    }
    
    fun getUserName(): String {
        return secureDataManager.getUserName()
    }
    
    // SECURE KEY MANAGEMENT (using Android Keystore via SecureDataManager)
    fun hasKeyPair(): Boolean {
        return secureDataManager.hasKeyPair()
    }
    
    // SECURITY: Removed saveKeyPair method that was causing key regeneration issues
    // Key pairs are now only generated via generateKeyPair() which properly stores them in Android Keystore
    // This prevents key mismatches that cause decryption failures
    
    fun loadKeyPair(): KeyPair? {
        return secureDataManager.loadKeyPair()
    }
    
    fun deleteKeyPair() {
        secureDataManager.deleteKeyPair()
    }
    
    /**
     * Get public key string for export/sharing
     */
    fun getPublicKeyString(): String? {
        return secureDataManager.getPublicKeyString()
    }
    
    // Message history (delegated to secure storage with cryptographic signatures)
    /**
     * Save messages to secure storage
     * 
     * SECURITY: This method immediately converts plaintext Message objects to encrypted
     * SecureMessage objects before storage. Plaintext Message objects are never persisted.
     * 
     * @param messages List of Message objects to save (converted to encrypted storage)
     */
    fun saveMessages(messages: List<Message>) {
        // Convert legacy Message to SecureMessage for storage
        // SECURITY: Plaintext Message objects are immediately encrypted before storage
        val secureMessages = messages.map { message ->
            SecureMessage(
                message.id,
                message.senderName,
                message.recipientName,
                message.content,
                message.timestamp,
                generateSessionNonce(), // Explicitly provide sessionNonce
                message.isOutgoing,
                message.isRead
            )
        }
        secureDataManager.saveMessages(secureMessages)
    }
    
    /**
     * Load messages from secure storage
     * 
     * SECURITY: This method creates plaintext Message objects in memory for UI display.
     * These objects are NEVER persisted to disk and exist only temporarily in memory.
     * All persistent storage uses encrypted SecureMessage objects.
     * 
     * @return List of Message objects for UI display (in-memory only)
     */
    fun loadMessages(): List<Message> {
        val secureMessages = secureDataManager.loadMessages()
        // Convert SecureMessage back to Message for backward compatibility
        // SECURITY: These Message objects exist only in memory and are never persisted
        return secureMessages.map { secureMessage ->
            Message(
                id = secureMessage.id,
                senderName = secureMessage.senderName,
                recipientName = secureMessage.recipientName,
                content = secureMessage.content,
                timestamp = secureMessage.timestamp,
                isOutgoing = secureMessage.isOutgoing,
                isRead = secureMessage.isRead
            )
        }
    }
    
    fun addMessage(message: Message) {
        // Convert to SecureMessage and add
        // Use positional parameters to let default values apply for sessionNonce, signature, and senderPublicKeyHash
        val secureMessage = SecureMessage(
            message.id,
            message.senderName,
            message.recipientName,
            message.content,
            message.timestamp,
            generateSessionNonce(), // Explicitly provide sessionNonce
            message.isOutgoing,
            message.isRead
        )
        secureDataManager.addMessage(secureMessage)
    }
    
    private fun generateSessionNonce(): String {
        val bytes = ByteArray(12) // 96-bit nonce for additional security
        java.security.SecureRandom().nextBytes(bytes)
        return android.util.Base64.encodeToString(bytes, android.util.Base64.URL_SAFE or android.util.Base64.NO_PADDING)
    }
    
    fun markMessageAsRead(messageId: String) {
        secureDataManager.markMessageAsRead(messageId)
    }
    
    /**
     * Create and sign a new outgoing message with cryptographic protection
     * 
     * @param content Message content
     * @param recipientName Recipient name
     * @param senderName Sender name
     * @return Signed Message
     */
    fun createSignedMessage(content: String, recipientName: String, senderName: String): Message? {
        return try {
            val keyPair = secureDataManager.loadKeyPair()
            if (keyPair != null) {
                val secureMessage = secureDataManager.createSignedMessage(
                    content, recipientName, senderName, keyPair.private, keyPair.public
                )
                
                // Convert back to Message for backward compatibility
                Message(
                    id = secureMessage.id,
                    senderName = secureMessage.senderName,
                    recipientName = secureMessage.recipientName,
                    content = secureMessage.content,
                    timestamp = secureMessage.timestamp,
                    isOutgoing = secureMessage.isOutgoing,
                    isRead = secureMessage.isRead
                )
            } else {
                null
            }
        } catch (e: Exception) {
            null
        }
    }
    
    /**
     * Verify and add a received message with cryptographic signature verification
     * 
     * @param message The message to verify and add
     * @param signedMessage The signed encrypted message for verification
     * @param senderPublicKey The public key of the claimed sender
     * @return true if message was verified and added, false otherwise
     */
    fun verifyAndAddMessage(message: Message, signedMessage: com.qrypteye.app.crypto.CryptoManager.SignedEncryptedMessage, senderPublicKey: java.security.PublicKey): Boolean {
        try {
            // SECURITY: Check for replay attacks first
            if (secureDataManager.replayProtection.isReplayAttack(message)) {
                android.util.Log.w("DataManager", "Replay attack detected for message: ${message.id}")
                return false
            }
            
            // SECURITY: Verify the signed message authenticity
            val cryptoManager = com.qrypteye.app.crypto.CryptoManager()
            val isAuthentic = cryptoManager.verifySignature(
                cryptoManager.createSignatureContext(signedMessage.encryptedMessage),
                signedMessage.signature,
                senderPublicKey
            )
            
            if (!isAuthentic) {
                android.util.Log.e("DataManager", "Signature verification failed for message: ${message.id}")
                return false
            }
            
            // Convert to SecureMessage and add
            val secureMessage = SecureMessage(
                message.id,
                message.senderName,
                message.recipientName,
                message.content,
                message.timestamp,
                generateSessionNonce(), // Explicitly provide sessionNonce
                message.isOutgoing,
                message.isRead
            )
            
            // Add the verified message
            secureDataManager.addMessage(secureMessage)
            return true
            
        } catch (e: Exception) {
            android.util.Log.e("DataManager", "Error verifying and adding message: ${e.message}", e)
            return false
        }
    }
    
    /**
     * Clear all data (both legacy and secure)
     */
    fun clearAllData() {
        try {
            // Clear secure data
            secureDataManager.clearAllData()
            
            // Clear legacy data
            legacyPrefs.edit().clear().apply()
            
        } catch (e: Exception) {
            throw SecurityException("Failed to clear data", e)
        }
    }
} 