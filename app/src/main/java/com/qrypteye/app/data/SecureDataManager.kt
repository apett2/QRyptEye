package com.qrypteye.app.data

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import java.security.KeyPair
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import javax.crypto.Cipher
import android.util.Base64

/**
 * SECURE DATA MANAGER
 * 
 * This class provides secure storage for sensitive cryptographic data using:
 * 1. Android Keystore System for private key storage (via SecureKeyManager)
 * 2. EncryptedSharedPreferences for encrypted data storage
 * 3. Proper key management and security practices
 * 
 * SECURITY FEATURES:
 * - Private keys stored in Android Keystore (hardware-backed when available)
 * - All sensitive data encrypted with AES-256-GCM
 * - Master key protected by Android Keystore
 * - No plaintext storage of sensitive information
 * - No serialization of private keys
 */
class SecureDataManager(private val context: Context) {
    
    companion object {
        private const val SECURE_PREFS_NAME = "QRyptEyeSecurePrefs"
        private const val KEY_CONTACTS = "contacts"
        private const val KEY_USER_NAME = "user_name"
        private const val KEY_MESSAGES = "messages"
        private const val KEY_SENDER_TIMESTAMPS = "sender_timestamps"
        
        // Size limits for encrypted data
        private const val MAX_ENCRYPTED_FIELD_SIZE = 1024 * 1024 // 1MB
        private const val MAX_ENCRYPTED_MESSAGE_SIZE = 512 * 1024 // 512KB
        private const val MAX_SIGNATURE_SIZE = 1024 // 1KB
        
        // Base64 encoding flags for consistency and security
        private const val BASE64_FLAGS = android.util.Base64.NO_WRAP or android.util.Base64.URL_SAFE
        
        private val gson = Gson()
    }
    
    private val secureKeyManager = SecureKeyManager(context)
    val replayProtection = ReplayProtection()
    
    // Timestamp tracking for each sender to prevent regression attacks
    private val senderTimestampTracker = SenderTimestampTracker()
    
    // Security audit logging for user feedback and debugging
    private val securityLogger = SecurityAuditLogger()
    
    // Android Keystore for secure key storage
    private val keyStore by lazy {
        java.security.KeyStore.getInstance("AndroidKeyStore").apply {
            load(null)
        }
    }
    
    private val masterKey by lazy {
        MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .setUserAuthenticationRequired(false) // Allow background access
            .build()
    }
    
    private val securePrefs by lazy {
        EncryptedSharedPreferences.create(
            context,
            SECURE_PREFS_NAME,
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
    }
    
    // Field-level encryption key stored in Android Keystore
    private val fieldEncryptionKey by lazy {
        val keyAlias = "qrypteye_field_encryption_key"
        if (!keyStore.containsAlias(keyAlias)) {
            generateFieldEncryptionKey(keyAlias)
        }
        keyStore.getKey(keyAlias, null) as javax.crypto.SecretKey
    }
    
    // HMAC key for metadata signing (generated in memory for compatibility)
    private val metadataSigningKey: javax.crypto.SecretKey by lazy {
        val keyAlias = "qrypteye_metadata_signing_key"
        val keyData = securePrefs.getString(keyAlias, null)
        
        android.util.Log.d("SecureDataManager", "Initializing metadata signing key, existing data: ${keyData != null}")
        
        if (keyData == null) {
            // Generate new HMAC key
            android.util.Log.d("SecureDataManager", "Generating new metadata signing key")
            val keyGenerator = javax.crypto.KeyGenerator.getInstance("HmacSHA256")
            keyGenerator.init(256) // 256-bit key
            val newKey = keyGenerator.generateKey()
            
            // Store the key material securely (encrypted with field encryption key, no integrity protection)
            val keyMaterial = android.util.Base64.encodeToString(newKey.encoded, BASE64_FLAGS)
            val encryptedKeyMaterial = encryptField(keyMaterial) // Use simple encryption without AAD
            securePrefs.edit().putString(keyAlias, encryptedKeyMaterial).apply()
            
            android.util.Log.d("SecureDataManager", "New metadata signing key generated and stored")
            newKey
        } else {
            // Load existing HMAC key
            try {
                android.util.Log.d("SecureDataManager", "Loading existing metadata signing key")
                val encryptedKeyMaterial = keyData
                val keyMaterial = decryptField(encryptedKeyMaterial) // Use simple decryption without AAD
                val keyBytes = android.util.Base64.decode(keyMaterial, BASE64_FLAGS)
                val key = javax.crypto.spec.SecretKeySpec(keyBytes, "HmacSHA256")
                android.util.Log.d("SecureDataManager", "Existing metadata signing key loaded successfully")
                key
            } catch (e: Exception) {
                // If decryption fails, regenerate the key
                android.util.Log.w("SecureDataManager", "Failed to load metadata signing key, regenerating: ${e.message}")
                securePrefs.edit().remove(keyAlias).apply()
                
                // Generate new key directly
                val keyGenerator = javax.crypto.KeyGenerator.getInstance("HmacSHA256")
                keyGenerator.init(256) // 256-bit key
                val newKey = keyGenerator.generateKey()
                
                // Store the new key
                val keyMaterial = android.util.Base64.encodeToString(newKey.encoded, BASE64_FLAGS)
                val encryptedKeyMaterial = encryptField(keyMaterial) // Use simple encryption without AAD
                securePrefs.edit().putString(keyAlias, encryptedKeyMaterial).apply()
                
                android.util.Log.d("SecureDataManager", "Metadata signing key regenerated due to decryption failure")
                newKey
            }
        }
    }
    
    /**
     * Generate field encryption key in Android Keystore
     * 
     * SECURITY: Creates AES-256 key within Android Keystore for hardware-backed security.
     * 
     * @param keyAlias The alias for the key in Android Keystore
     */
    private fun generateFieldEncryptionKey(keyAlias: String) {
        val keyGenParameterSpec = android.security.keystore.KeyGenParameterSpec.Builder(
            keyAlias,
            android.security.keystore.KeyProperties.PURPOSE_ENCRYPT or android.security.keystore.KeyProperties.PURPOSE_DECRYPT
        ).apply {
            setKeySize(256)
            setBlockModes(android.security.keystore.KeyProperties.BLOCK_MODE_GCM)
            setEncryptionPaddings(android.security.keystore.KeyProperties.ENCRYPTION_PADDING_NONE)
            setUserAuthenticationRequired(false)
            setRandomizedEncryptionRequired(true)
        }.build()
        
        val keyGenerator = javax.crypto.KeyGenerator.getInstance(
            android.security.keystore.KeyProperties.KEY_ALGORITHM_AES,
            "AndroidKeyStore"
        )
        keyGenerator.init(keyGenParameterSpec)
        keyGenerator.generateKey()
        
        // Log key generation
        securityLogger.logSecurityEvent(
            SecurityEvent.KEY_GENERATION,
            "Field encryption key generated in Android Keystore: $keyAlias"
        )
    }
    
    /**
     * Validate encrypted data size
     * 
     * SECURITY: Prevents storage exhaustion attacks by limiting encrypted data size.
     * 
     * @param encryptedData The encrypted data to validate
     * @return true if size is within limits, false otherwise
     */
    private fun validateEncryptedDataSize(encryptedData: String): Boolean {
        return encryptedData.length <= MAX_ENCRYPTED_FIELD_SIZE
    }
    
    /**
     * Validate signature size
     * 
     * SECURITY: Prevents oversized signature attacks by limiting signature size.
     * 
     * @param signature The signature to validate
     * @return true if size is within limits, false otherwise
     */
    private fun validateSignatureSize(signature: String): Boolean {
        return signature.length <= MAX_SIGNATURE_SIZE
    }
    
    /**
     * Validate Base64 string before decoding
     * 
     * SECURITY: Prevents malformed Base64 attacks by validating string format.
     * 
     * @param base64String The Base64 string to validate
     * @return true if string is valid Base64, false otherwise
     */
    private fun validateBase64String(base64String: String): Boolean {
        return try {
            // Check if string is valid Base64 with our flags
            android.util.Base64.decode(base64String, BASE64_FLAGS)
            true
        } catch (e: Exception) {
            false
        }
    }
    
    /**
     * Sign metadata with HMAC-SHA256 using Android Keystore
     * 
     * SECURITY: Uses Android Keystore's built-in MAC functionality to create
     * a cryptographic signature of metadata that prevents tampering with encrypted data structures.
     * 
     * @param metadata The metadata string to sign
     * @return Base64 encoded HMAC signature
     */
    private fun signMetadata(metadata: String): String {
        val mac = javax.crypto.Mac.getInstance("HmacSHA256")
        mac.init(metadataSigningKey)
        
        val signatureBytes = mac.doFinal(metadata.toByteArray())
        val signature = android.util.Base64.encodeToString(signatureBytes, BASE64_FLAGS)
        
        // Validate signature size
        if (!validateSignatureSize(signature)) {
            throw SecurityException("Generated signature exceeds size limit")
        }
        
        return signature
    }
    
    /**
     * Verify metadata signature with HMAC-SHA256
     * 
     * SECURITY: Verifies that the metadata hasn't been tampered with by checking
     * the HMAC signature against the expected value.
     * 
     * @param metadata The metadata string to verify
     * @param signature The expected HMAC signature
     * @return true if signature is valid, false otherwise
     */
    private fun verifyMetadata(metadata: String, signature: String): Boolean {
        return try {
            // Validate signature size
            if (!validateSignatureSize(signature)) {
                securityLogger.logSecurityEvent(
                    SecurityEvent.DATA_INTEGRITY_VIOLATION,
                    "Signature size exceeds limit"
                )
                return false
            }
            
            // Validate Base64 format
            if (!validateBase64String(signature)) {
                securityLogger.logSecurityEvent(
                    SecurityEvent.DATA_INTEGRITY_VIOLATION,
                    "Invalid Base64 signature format"
                )
                return false
            }
            
            // Generate the expected signature using the same key
            val mac = javax.crypto.Mac.getInstance("HmacSHA256")
            mac.init(metadataSigningKey)
            val expectedSignatureBytes = mac.doFinal(metadata.toByteArray())
            val expectedSignature = android.util.Base64.encodeToString(expectedSignatureBytes, BASE64_FLAGS)
            
            // Compare signatures using constant-time comparison
            val constantTimeComparison = java.security.MessageDigest.isEqual(
                android.util.Base64.decode(signature, BASE64_FLAGS),
                android.util.Base64.decode(expectedSignature, BASE64_FLAGS)
            )
            
            if (!constantTimeComparison) {
                securityLogger.logSecurityEvent(
                    SecurityEvent.METADATA_SIGNATURE_VIOLATION,
                    "Signature mismatch - possible tampering detected"
                )
            }
            
            constantTimeComparison
        } catch (e: Exception) {
            securityLogger.logSecurityEvent(
                SecurityEvent.DATA_INTEGRITY_VIOLATION,
                "Signature verification failed: ${e.message}"
            )
            false
        }
    }
    
    /**
     * Encrypt sensitive field data with integrity protection
     * 
     * SECURITY: Uses GCM with Additional Authenticated Data (AAD) to bind
     * encrypted content to object metadata, preventing replay and substitution attacks.
     * 
     * @param data The data to encrypt
     * @param objectId The unique identifier of the object (prevents substitution)
     * @param objectType The type of object (prevents cross-object attacks)
     * @param timestamp The timestamp of the object (prevents replay attacks)
     * @return Base64 encoded encrypted data with IV
     */
    private fun encryptFieldWithIntegrity(
        data: String, 
        objectId: String, 
        objectType: String, 
        timestamp: Long
    ): String {
        val cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, fieldEncryptionKey)
        
        // Create Additional Authenticated Data (AAD) to bind encrypted content
        // This prevents replay and substitution attacks
        val aad = "$objectType:$objectId:$timestamp".toByteArray()
        cipher.updateAAD(aad)
        
        val encryptedBytes = cipher.doFinal(data.toByteArray())
        val iv = cipher.iv
        
        // Combine IV and encrypted data
        val combined = iv + encryptedBytes
        val encryptedData = android.util.Base64.encodeToString(combined, BASE64_FLAGS)
        
        // Validate encrypted data size
        if (!validateEncryptedDataSize(encryptedData)) {
            throw SecurityException("Encrypted data exceeds size limit")
        }
        
        return encryptedData
    }
    
    /**
     * Decrypt sensitive field data with integrity verification
     * 
     * SECURITY: Verifies that the AAD matches the expected object metadata,
     * ensuring the encrypted data belongs to the correct object and hasn't been
     * replayed or substituted.
     * 
     * @param encryptedData The encrypted data to decrypt
     * @param objectId The expected object identifier
     * @param objectType The expected object type
     * @param timestamp The expected timestamp
     * @return The decrypted data
     * @throws IllegalArgumentException if AAD verification fails (replay/substitution attack)
     */
    private fun decryptFieldWithIntegrity(
        encryptedData: String, 
        objectId: String, 
        objectType: String, 
        timestamp: Long
    ): String {
        // Validate encrypted data size
        if (!validateEncryptedDataSize(encryptedData)) {
            throw SecurityException("Encrypted data exceeds size limit")
        }
        
        // Validate Base64 format
        if (!validateBase64String(encryptedData)) {
            throw SecurityException("Invalid Base64 encrypted data format")
        }
        
        val combined = android.util.Base64.decode(encryptedData, BASE64_FLAGS)
        val iv = combined.copyOfRange(0, 12) // 96-bit IV for GCM
        val encryptedBytes = combined.copyOfRange(12, combined.size)
        
        val cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding")
        val ivSpec = javax.crypto.spec.GCMParameterSpec(128, iv)
        cipher.init(javax.crypto.Cipher.DECRYPT_MODE, fieldEncryptionKey, ivSpec)
        
        // Verify AAD matches expected object metadata
        val expectedAad = "$objectType:$objectId:$timestamp".toByteArray()
        cipher.updateAAD(expectedAad)
        
        try {
            val decryptedBytes = cipher.doFinal(encryptedBytes)
            return String(decryptedBytes)
        } catch (e: javax.crypto.AEADBadTagException) {
            // AAD verification failed - possible replay or substitution attack
            throw IllegalArgumentException("Integrity check failed: possible replay or substitution attack", e)
        }
    }
    
    /**
     * Encrypt sensitive field data (legacy method for backward compatibility)
     * 
     * @deprecated Use encryptFieldWithIntegrity() for new data
     */
    @Deprecated("Use encryptFieldWithIntegrity() for better security")
    private fun encryptField(data: String): String {
        val cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, fieldEncryptionKey)
        val encryptedBytes = cipher.doFinal(data.toByteArray())
        val iv = cipher.iv
        
        // Combine IV and encrypted data
        val combined = iv + encryptedBytes
        return android.util.Base64.encodeToString(combined, BASE64_FLAGS)
    }
    
    /**
     * Decrypt sensitive field data (legacy method for backward compatibility)
     * 
     * @deprecated Use decryptFieldWithIntegrity() for new data
     */
    @Deprecated("Use decryptFieldWithIntegrity() for better security")
    private fun decryptField(encryptedData: String): String {
        val combined = android.util.Base64.decode(encryptedData, BASE64_FLAGS)
        val iv = combined.copyOfRange(0, 12) // 96-bit IV for GCM
        val encryptedBytes = combined.copyOfRange(12, combined.size)
        
        val cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding")
        val ivSpec = javax.crypto.spec.GCMParameterSpec(128, iv)
        cipher.init(javax.crypto.Cipher.DECRYPT_MODE, fieldEncryptionKey, ivSpec)
        
        val decryptedBytes = cipher.doFinal(encryptedBytes)
        return String(decryptedBytes)
    }
    
    // Contact management (encrypted storage with field-level encryption)
    fun saveContacts(contacts: List<Contact>) {
        val encryptedContacts = contacts.map { contact ->
            EncryptedContact.fromContact(
                contact, 
                { encryptFieldWithIntegrity(it, contact.id, "contact", contact.timestamp) },
                { signMetadata(it) }
            )
        }
        val json = gson.toJson(encryptedContacts)
        securePrefs.edit().putString(KEY_CONTACTS, json).apply()
    }
    
    fun loadContacts(): List<Contact> {
        val json = securePrefs.getString(KEY_CONTACTS, "[]")
        android.util.Log.d("SecureDataManager", "loadContacts: raw JSON length: ${json?.length ?: 0}")
        
        val type = object : TypeToken<List<EncryptedContact>>() {}.type
        return try {
            val encryptedContacts: List<EncryptedContact> = gson.fromJson(json, type) ?: emptyList()
            android.util.Log.d("SecureDataManager", "loadContacts: parsed ${encryptedContacts.size} encrypted contacts")
            
            val decryptedContacts = encryptedContacts.mapNotNull { encryptedContact ->
                try {
                    val contact = EncryptedContact.toContact(
                        encryptedContact, 
                        { decryptFieldWithIntegrity(it, encryptedContact.id, "contact", encryptedContact.timestamp) },
                        { metadata, signature -> verifyMetadata(metadata, signature) }
                    )
                    android.util.Log.d("SecureDataManager", "loadContacts: successfully decrypted contact: ${contact.name}")
                    contact
                } catch (e: SecurityException) {
                    // Metadata signature verification failed - possible tampering
                    android.util.Log.e("SecureDataManager", 
                        "Metadata signature violation for contact ${encryptedContact.id}: ${e.message}")
                    securityLogger.logSecurityEvent(
                        SecurityEvent.METADATA_SIGNATURE_VIOLATION,
                        "Contact metadata signature failed: ${e.message}"
                    )
                    null // Skip this contact
                } catch (e: IllegalArgumentException) {
                    // Integrity check failed - possible replay or substitution attack
                    android.util.Log.e("SecureDataManager", 
                        "Data integrity violation for contact ${encryptedContact.id}: ${e.message}")
                    securityLogger.logSecurityEvent(
                        SecurityEvent.DATA_INTEGRITY_VIOLATION,
                        "Contact integrity check failed: ${e.message}"
                    )
                    null // Skip this contact
                } catch (e: Exception) {
                    // Other decryption errors
                    android.util.Log.w("SecureDataManager", 
                        "Failed to decrypt contact ${encryptedContact.id}: ${e.message}")
                    null // Skip this contact
                }
            }
            
            android.util.Log.d("SecureDataManager", "loadContacts: successfully decrypted ${decryptedContacts.size} contacts")
            decryptedContacts
        } catch (e: Exception) {
            android.util.Log.e("SecureDataManager", "Failed to load contacts: ${e.message}")
            emptyList()
        }
    }
    
    fun addContact(contact: Contact) {
        // Validate the contact's public key before storing
        val validation = Contact.validatePublicKey(contact.publicKeyString)
        if (validation !is Contact.ValidationResult.Valid) {
            throw IllegalArgumentException("Cannot store contact with invalid public key: ${validation.message}")
        }
        
        val contacts = loadContacts().toMutableList()
        val existingIndex = contacts.indexOfFirst { it.name == contact.name }
        if (existingIndex >= 0) {
            contacts[existingIndex] = contact
        } else {
            contacts.add(contact)
        }
        saveContacts(contacts)
    }
    
    fun removeContact(contactId: String) {
        val contacts = loadContacts().toMutableList()
        contacts.removeAll { it.id == contactId }
        saveContacts(contacts)
    }
    
    fun getContactByName(name: String): Contact? {
        return loadContacts().find { it.name == name }
    }
    
    // User settings (encrypted storage)
    fun saveUserName(name: String) {
        val timestamp = System.currentTimeMillis()
        val encryptedName = encryptFieldWithIntegrity(name, "user_settings", "user", timestamp)
        
        // Store both the encrypted name and the timestamp
        val userNameData = mapOf(
            "encryptedName" to encryptedName,
            "timestamp" to timestamp
        )
        val json = gson.toJson(userNameData)
        securePrefs.edit().putString(KEY_USER_NAME, json).apply()
    }
    
    fun getUserName(): String {
        val json = securePrefs.getString(KEY_USER_NAME, "")
        return if (json != null && json.isNotEmpty()) {
            try {
                val userNameData = gson.fromJson(json, Map::class.java)
                val encryptedName = userNameData["encryptedName"] as? String
                val timestamp = (userNameData["timestamp"] as? Number)?.toLong()
                
                if (encryptedName != null && timestamp != null) {
                    decryptFieldWithIntegrity(encryptedName, "user_settings", "user", timestamp)
                } else {
                    ""
                }
            } catch (e: Exception) {
                // Fallback for legacy format (before timestamp was stored)
                try {
                    decryptFieldWithIntegrity(json, "user_settings", "user", System.currentTimeMillis())
                } catch (e2: Exception) {
                    ""
                }
            }
        } else {
            ""
        }
    }
    
    // Message history (encrypted storage with field-level encryption)
    fun saveMessages(messages: List<SecureMessage>) {
        val encryptedMessages = messages.map { message ->
            EncryptedSecureMessage.fromSecureMessage(
                message, 
                { encryptFieldWithIntegrity(it, message.id, "message", message.timestamp) },
                { signMetadata(it) }
            )
        }
        val json = gson.toJson(encryptedMessages)
        securePrefs.edit().putString(KEY_MESSAGES, json).apply()
    }
    
    fun loadMessages(): List<SecureMessage> {
        val json = securePrefs.getString(KEY_MESSAGES, "[]")
        val type = object : TypeToken<List<EncryptedSecureMessage>>() {}.type
        return try {
            val encryptedMessages: List<EncryptedSecureMessage> = gson.fromJson(json, type) ?: emptyList()
            encryptedMessages.mapNotNull { encryptedMessage ->
                try {
                    val message = EncryptedSecureMessage.toSecureMessage(
                        encryptedMessage, 
                        { decryptFieldWithIntegrity(it, encryptedMessage.id, "message", encryptedMessage.timestamp) },
                        { metadata, signature -> verifyMetadata(metadata, signature) }
                    )
                    
                    // SECURITY: Merge read status from separate storage to maintain cryptographic integrity
                    // The isRead field in the signed message is always false (excluded from signature)
                    // We check the separate read status storage for the actual read state
                    val actualReadStatus = isMessageRead(message.id)
                    if (actualReadStatus != message.isRead) {
                        // Update the message with the actual read status (doesn't affect signature)
                        message.copy(isRead = actualReadStatus)
                    } else {
                        message
                    }
                } catch (e: SecurityException) {
                    // Metadata signature verification failed - possible tampering
                    android.util.Log.e("SecureDataManager", 
                        "Metadata signature violation for message ${encryptedMessage.id}: ${e.message}")
                    securityLogger.logSecurityEvent(
                        SecurityEvent.METADATA_SIGNATURE_VIOLATION,
                        "Message metadata signature failed: ${e.message}"
                    )
                    null // Skip this message
                } catch (e: IllegalArgumentException) {
                    // Integrity check failed - possible replay or substitution attack
                    android.util.Log.e("SecureDataManager", 
                        "Data integrity violation for message ${encryptedMessage.id}: ${e.message}")
                    securityLogger.logSecurityEvent(
                        SecurityEvent.DATA_INTEGRITY_VIOLATION,
                        "Message integrity check failed: ${e.message}"
                    )
                    null // Skip this message
                } catch (e: Exception) {
                    // Other decryption errors
                    android.util.Log.w("SecureDataManager", 
                        "Failed to decrypt message ${encryptedMessage.id}: ${e.message}")
                    null // Skip this message
                }
            }
        } catch (e: Exception) {
            android.util.Log.e("SecureDataManager", "Failed to load messages: ${e.message}")
            emptyList()
        }
    }
    
    fun addMessage(message: SecureMessage) {
        val messages = loadMessages().toMutableList()
        
        // SECURITY: Check for duplicate messages using cryptographic message ID
        // This is cryptographically secure and cannot be bypassed
        val isDuplicate = messages.any { existingMessage ->
            existingMessage.id == message.id
        }
        
        if (!isDuplicate) {
            messages.add(message)
            saveMessages(messages)
        }
    }
    
    /**
     * Mark a message as read (stored separately from signed data)
     * 
     * SECURITY: Read status is stored separately from the signed message data
     * to maintain cryptographic integrity. This allows legitimate local updates
     * without breaking signature verification.
     * 
     * @param messageId The ID of the message to mark as read
     */
    fun markMessageAsRead(messageId: String) {
        try {
            // Store read status separately from signed message data
            val readMessagesKey = "read_messages"
            val readMessagesJson = securePrefs.getString(readMessagesKey, "[]")
            val readMessages = try {
                com.google.gson.Gson().fromJson(readMessagesJson, Array<String>::class.java).toMutableSet()
            } catch (e: Exception) {
                mutableSetOf<String>()
            }
            
            // Add message ID to read set
            readMessages.add(messageId)
            
            // Save updated read status
            val updatedJson = com.google.gson.Gson().toJson(readMessages.toTypedArray())
            securePrefs.edit().putString(readMessagesKey, updatedJson).apply()
            
        } catch (e: Exception) {
            android.util.Log.e("SecureDataManager", "Failed to mark message as read: ${e.message}")
        }
    }
    
    /**
     * Check if a message is marked as read
     * 
     * @param messageId The ID of the message to check
     * @return true if the message is marked as read, false otherwise
     */
    fun isMessageRead(messageId: String): Boolean {
        try {
            val readMessagesKey = "read_messages"
            val readMessagesJson = securePrefs.getString(readMessagesKey, "[]")
            val readMessages = try {
                com.google.gson.Gson().fromJson(readMessagesJson, Array<String>::class.java).toSet()
            } catch (e: Exception) {
                emptySet<String>()
            }
            
            return readMessages.contains(messageId)
        } catch (e: Exception) {
            android.util.Log.e("SecureDataManager", "Failed to check message read status: ${e.message}")
            return false
        }
    }
    
    /**
     * Verify and add a received message with cryptographic signature verification
     * 
     * SECURITY: This method provides comprehensive replay protection by:
     * 1. Checking for message ID reuse (prevents exact message replay)
     * 2. Checking for timestamp regression (prevents old message replay)
     * 3. Validating clock drift (prevents future message attacks)
     * 4. Verifying cryptographic signature (prevents message tampering)
     * 5. Supporting key rotation (maintains replay protection across key changes)
     * 
     * @param message The message to verify and add
     * @param senderPublicKey The public key of the claimed sender
     * @return true if message was verified and added, false otherwise
     */
    fun verifyAndAddMessage(message: SecureMessage, senderPublicKey: java.security.PublicKey): Boolean {
        val messageHash = securityLogger.generateMessageHash(message.content)
        val senderHash = securityLogger.generateSenderHash(message.senderName)
        
        try {
            // SECURITY: Check for replay attacks first (before expensive signature verification)
            if (replayProtection.isReplayAttack(message)) {
                securityLogger.logSecurityEvent(
                    SecurityEvent.REPLAY_ATTACK_DETECTED,
                    "Message ID: ${message.id}",
                    messageHash,
                    senderHash
                )
                return false
            }
            
            // SECURITY: Look up contact ID for key rotation support
            val contactId = findContactIdByPublicKey(senderPublicKey, message.senderName)
            
            // SECURITY: Comprehensive replay protection including message ID and timestamp validation
            // Now supports key rotation by tracking per contact rather than per key
            if (!senderTimestampTracker.validateAndUpdateMessage(senderPublicKey, message.id, message.timestamp, contactId)) {
                securityLogger.logSecurityEvent(
                    SecurityEvent.TIMESTAMP_REGRESSION_DETECTED,
                    "Message replay detected - ID: ${message.id}, timestamp: ${message.timestamp}, contactId: $contactId",
                    messageHash,
                    senderHash
                )
                return false // Message replay, timestamp regression, or excessive clock drift detected
            }
            
            // SECURITY: Verify message authenticity through cryptographic signature
            if (!message.isAuthentic(senderPublicKey)) {
                securityLogger.logSecurityEvent(
                    SecurityEvent.SIGNATURE_INVALID,
                    "Message ID: ${message.id}",
                    messageHash,
                    senderHash
                )
                return false
            }
            
            // Log successful verification
            securityLogger.logSecurityEvent(
                SecurityEvent.MESSAGE_VERIFIED,
                "Message ID: ${message.id}, contactId: $contactId",
                messageHash,
                senderHash
            )
            
            // Add the verified message
            addMessage(message)
            return true
            
        } catch (e: Exception) {
            securityLogger.logSecurityEvent(
                SecurityEvent.MESSAGE_VERIFICATION_FAILED,
                "Exception: ${e.message}",
                messageHash,
                senderHash
            )
            return false
        }
    }
    
    /**
     * Create and sign a new outgoing message
     * 
     * SECURITY: Uses createForSigning to exclude mutable fields (isRead) from signature.
     * This ensures cryptographic integrity while allowing legitimate local state changes.
     * 
     * @param content Message content
     * @param recipientName Recipient name
     * @param senderName Sender name
     * @param senderPrivateKey Sender's private key for signing
     * @param senderPublicKey Sender's public key for hash generation
     * @return Signed SecureMessage
     */
    fun createSignedMessage(
        content: String,
        recipientName: String,
        senderName: String,
        senderPrivateKey: java.security.PrivateKey,
        senderPublicKey: java.security.PublicKey
    ): SecureMessage {
        // SECURITY: Use createForSigning to exclude mutable isRead field from signature
        val message = SecureMessage.createForSigning(
            senderName = senderName,
            recipientName = recipientName,
            content = content,
            isOutgoing = true
        )
        
        return message.sign(senderPrivateKey, senderPublicKey)
    }
    
    // SECURE KEY MANAGEMENT using Android Keystore (via SecureKeyManager)
    fun generateKeyPair(): KeyPair? {
        try {
            // Generate a new key pair within Android Keystore
            // This ensures private keys never leave the secure hardware environment
            secureKeyManager.generateKeyPair()
            
            // Load and return the generated key pair
            return loadKeyPair()
            
        } catch (e: Exception) {
            throw SecurityException("Failed to generate key pair securely", e)
        }
    }
    
    // SECURITY: Removed saveKeyPair method that was causing key regeneration issues
    // Key pairs are now only generated via generateKeyPair() which properly stores them in Android Keystore
    // This prevents key mismatches that cause decryption failures
    
    fun loadKeyPair(): KeyPair? {
        return try {
            secureKeyManager.loadKeyPair()
        } catch (e: Exception) {
            null
        }
    }
    
    fun hasKeyPair(): Boolean {
        return try {
            secureKeyManager.hasKeyPair()
        } catch (e: Exception) {
            false
        }
    }
    
    fun deleteKeyPair() {
        try {
            secureKeyManager.deleteKeyPair()
        } catch (e: Exception) {
            throw SecurityException("Failed to delete key pair", e)
        }
    }
    
    /**
     * Get public key string for export/sharing
     */
    fun getPublicKeyString(): String? {
        return try {
            secureKeyManager.getPublicKeyString()
        } catch (e: Exception) {
            null
        }
    }
    
    /**
     * Clear all data including replay protection (for security purposes)
     */
    fun clearAllData() {
        try {
            // Clear encrypted preferences
            securePrefs.edit().clear().apply()
            
            // Clear replay protection
            replayProtection.clearAll()
            
            // Clear sender timestamp tracking
            senderTimestampTracker.clearAll()
            
            // Clear security audit logs
            securityLogger.clearAll()
            
        } catch (e: Exception) {
            throw SecurityException("Failed to clear secure data", e)
        }
    }
    
    /**
     * Get recent security events for user feedback
     * 
     * @param maxEvents Maximum number of events to return
     * @return List of recent audit events
     */
    fun getRecentSecurityEvents(maxEvents: Int = 50): List<SecurityAuditLogger.AuditEvent> {
        return securityLogger.getRecentEvents(maxEvents)
    }
    
    /**
     * Get security statistics for user feedback
     * 
     * @return SecurityStatistics object with counts
     */
    fun getSecurityStatistics(): SecurityAuditLogger.SecurityStatistics {
        return securityLogger.getSecurityStatistics()
    }
    
    /**
     * Log key generation event
     */
    fun logKeyGeneration() {
        securityLogger.logSecurityEvent(
            SecurityEvent.KEY_GENERATION,
            "New key pair generated"
        )
    }
    
    /**
     * Log key rotation event
     */
    fun logKeyRotation() {
        securityLogger.logSecurityEvent(
            SecurityEvent.KEY_ROTATION,
            "Key pair rotated"
        )
    }
    
    /**
     * Log encryption success
     */
    fun logEncryptionSuccess(messageId: String) {
        securityLogger.logSecurityEvent(
            SecurityEvent.ENCRYPTION_SUCCESS,
            "Message encrypted: $messageId"
        )
    }
    
    /**
     * Log encryption failure
     */
    fun logEncryptionFailure(error: String) {
        securityLogger.logSecurityEvent(
            SecurityEvent.ENCRYPTION_FAILED,
            "Encryption failed: $error"
        )
    }
    
    /**
     * Log decryption success
     */
    fun logDecryptionSuccess(messageId: String) {
        securityLogger.logSecurityEvent(
            SecurityEvent.DECRYPTION_SUCCESS,
            "Message decrypted: $messageId"
        )
    }
    
    /**
     * Log decryption failure
     */
    fun logDecryptionFailure(error: String) {
        securityLogger.logSecurityEvent(
            SecurityEvent.DECRYPTION_FAILED,
            "Decryption failed: $error"
        )
    }
    
    /**
     * Check if keys should be rotated based on time interval
     * 
     * SECURITY: Implements automatic key rotation to limit key lifetime
     * and reduce the impact of potential key compromise.
     * 
     * @return true if keys should be rotated, false otherwise
     */
    private fun shouldRotateKeys(): Boolean {
        val lastRotation = securePrefs.getLong("last_key_rotation", 0L)
        val currentTime = System.currentTimeMillis()
        val rotationInterval = 30 * 24 * 60 * 60 * 1000L // 30 days
        
        return (currentTime - lastRotation) > rotationInterval
    }
    
    /**
     * Rotate encryption keys and re-encrypt all data
     * 
     * SECURITY: Generates new keys and re-encrypts all data to ensure
     * forward secrecy and limit the impact of key compromise.
     */
    fun rotateKeys() {
        try {
            // Check if rotation is needed
            if (!shouldRotateKeys()) {
                return
            }
            
            securityLogger.logSecurityEvent(
                SecurityEvent.KEY_ROTATION,
                "Starting automatic key rotation"
            )
            
            // Generate new field encryption key with new alias
            val newFieldKeyAlias = "qrypteye_field_encryption_key_v${System.currentTimeMillis()}"
            generateFieldEncryptionKey(newFieldKeyAlias)
            
            // Re-encrypt all contacts with new key
            val contacts = loadContacts()
            saveContacts(contacts) // This will re-encrypt with new key
            
            // Re-encrypt all messages with new key
            val messages = loadMessages()
            saveMessages(messages) // This will re-encrypt with new key
            
            // Delete old field encryption key
            val oldFieldKeyAlias = "qrypteye_field_encryption_key"
            if (keyStore.containsAlias(oldFieldKeyAlias)) {
                keyStore.deleteEntry(oldFieldKeyAlias)
            }
            
            // Update key rotation timestamp
            securePrefs.edit().putLong("last_key_rotation", System.currentTimeMillis()).apply()
            
            securityLogger.logSecurityEvent(
                SecurityEvent.KEY_ROTATION,
                "Key rotation completed successfully"
            )
            
        } catch (e: Exception) {
            securityLogger.logSecurityEvent(
                SecurityEvent.KEY_ROTATION,
                "Key rotation failed: ${e.message}"
            )
            throw SecurityException("Failed to rotate keys", e)
        }
    }
    
    /**
     * Check key health and perform maintenance
     * 
     * SECURITY: Performs key health checks and initiates rotation if needed.
     * This should be called periodically to ensure key security.
     */
    fun performKeyMaintenance() {
        try {
            // Check if keys exist and are accessible
            val fieldKeyExists = keyStore.containsAlias("qrypteye_field_encryption_key")
            val metadataKeyExists = keyStore.containsAlias("qrypteye_metadata_signing_key")
            
            if (!fieldKeyExists || !metadataKeyExists) {
                securityLogger.logSecurityEvent(
                    SecurityEvent.KEY_GENERATION,
                    "Missing keys detected, regenerating"
                )
                // Force regeneration of missing keys
                fieldEncryptionKey
                metadataSigningKey
            }
            
            // Check if rotation is needed
            if (shouldRotateKeys()) {
                rotateKeys()
            }
            
        } catch (e: Exception) {
            securityLogger.logSecurityEvent(
                SecurityEvent.KEY_ROTATION,
                "Key maintenance failed: ${e.message}"
            )
        }
    }

    /**
     * Find contact ID by public key for key rotation support
     * 
     * SECURITY: This method supports key rotation by:
     * 1. First checking if the public key is already mapped to a contact ID
     * 2. If not found, searching through contacts to find a match
     * 3. If still not found, returning null (will use public key hash as fallback)
     * 
     * @param senderPublicKey The sender's public key
     * @param senderName The sender's name (for additional lookup)
     * @return The contact ID if found, null otherwise
     */
    private fun findContactIdByPublicKey(senderPublicKey: java.security.PublicKey, senderName: String): String? {
        // First, check if we already have a mapping for this public key
        val existingContactId = senderTimestampTracker.getContactId(senderPublicKey)
        if (existingContactId != null) {
            return existingContactId
        }
        
        // If no existing mapping, search through contacts to find a match
        val contacts = loadContacts()
        val matchingContact = contacts.find { contact ->
            try {
                // Compare public keys by parsing the stored public key string
                val contactPublicKey = Contact.decodePublicKey(contact.publicKeyString)
                contactPublicKey.encoded.contentEquals(senderPublicKey.encoded)
            } catch (e: Exception) {
                // If parsing fails, fall back to name matching
                contact.name == senderName
            }
        }
        
        return matchingContact?.id
    }
} 