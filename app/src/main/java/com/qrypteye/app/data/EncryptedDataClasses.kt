package com.qrypteye.app.data

import android.util.Base64
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * ENCRYPTED DATA CLASSES
 * 
 * These classes represent encrypted versions of sensitive data for storage.
 * Sensitive fields are encrypted at rest to prevent data leakage.
 * 
 * SECURITY: All sensitive fields are encrypted with AES-256-GCM with integrity protection
 * before being stored in EncryptedSharedPreferences.
 * 
 * INTEGRITY PROTECTION:
 * - Additional Authenticated Data (AAD) binds encrypted content to object metadata
 * - Prevents replay attacks by including timestamps in AAD
 * - Prevents substitution attacks by including object IDs in AAD
 * - GCM authentication ensures data integrity and authenticity
 * - HMAC signatures protect entire encrypted data structures
 * - Prevents attacker-controlled payload injection
 */

/**
 * Encrypted contact data for storage with metadata signing
 */
data class EncryptedContact(
    val id: String,
    val nameEncrypted: String,  // Encrypted contact name with integrity protection
    val publicKeyString: String,  // Public keys can remain unencrypted
    val timestamp: Long,
    val metadataSignature: String  // HMAC signature of metadata to prevent tampering
) {
    companion object {
        fun fromContact(contact: Contact, encryptField: (String) -> String, signMetadata: (String) -> String): EncryptedContact {
            val encryptedContact = EncryptedContact(
                id = contact.id,
                nameEncrypted = encryptField(contact.name),
                publicKeyString = contact.publicKeyString,
                timestamp = contact.timestamp,
                metadataSignature = "" // Will be set after creation
            )
            
            // Generate HMAC signature of metadata (excluding the signature field itself)
            val metadataToSign = buildString {
                append("contact:")
                append(encryptedContact.id)
                append(":")
                append(encryptedContact.nameEncrypted)
                append(":")
                append(encryptedContact.publicKeyString)
                append(":")
                append(encryptedContact.timestamp)
            }
            
            return encryptedContact.copy(
                metadataSignature = signMetadata(metadataToSign)
            )
        }
        
        fun toContact(encryptedContact: EncryptedContact, decryptField: (String) -> String, verifyMetadata: (String, String) -> Boolean): Contact {
            // Verify metadata signature before processing
            val metadataToVerify = buildString {
                append("contact:")
                append(encryptedContact.id)
                append(":")
                append(encryptedContact.nameEncrypted)
                append(":")
                append(encryptedContact.publicKeyString)
                append(":")
                append(encryptedContact.timestamp)
            }
            
            if (!verifyMetadata(metadataToVerify, encryptedContact.metadataSignature)) {
                throw SecurityException("Metadata signature verification failed - possible tampering detected")
            }
            
            // Validate the public key before creating the Contact object
            val validation = Contact.validatePublicKey(encryptedContact.publicKeyString)
            if (validation !is Contact.ValidationResult.Valid) {
                throw IllegalArgumentException("Invalid public key in encrypted contact: ${validation.message}")
            }
            
            return Contact(
                id = encryptedContact.id,
                name = decryptField(encryptedContact.nameEncrypted),
                publicKeyString = encryptedContact.publicKeyString,
                timestamp = encryptedContact.timestamp
            )
        }
    }
}

/**
 * ENCRYPTED SECURE MESSAGE
 * 
 * This class represents an encrypted SecureMessage with integrity protection.
 * 
 * SECURITY FEATURES:
 * - All sensitive fields are encrypted with field-level encryption
 * - Metadata signing prevents tampering with encrypted structure
 * - Session nonce is preserved for replay protection
 * - Cryptographic signatures are preserved for verification
 * - AAD-based integrity protection for each encrypted field
 */
data class EncryptedSecureMessage(
    val id: String,
    val senderNameEncrypted: String,  // Encrypted sender name with integrity protection
    val recipientNameEncrypted: String,  // Encrypted recipient name with integrity protection
    val contentEncrypted: String,  // Encrypted message content with integrity protection
    val timestamp: Long,
    val sessionNonce: String,  // Session nonce for replay protection (preserved)
    val isOutgoing: Boolean,
    val isRead: Boolean,
    val signature: String?,  // Cryptographic signature (unencrypted for verification)
    val senderPublicKeyHash: String?,  // Hash of sender's public key (unencrypted)
    val metadataSignature: String  // HMAC signature of metadata to prevent tampering
) {
    companion object {
        fun fromSecureMessage(secureMessage: SecureMessage, encryptField: (String) -> String, signMetadata: (String) -> String): EncryptedSecureMessage {
            val encryptedMessage = EncryptedSecureMessage(
                id = secureMessage.id,
                senderNameEncrypted = encryptField(secureMessage.senderName),
                recipientNameEncrypted = encryptField(secureMessage.recipientName),
                contentEncrypted = encryptField(secureMessage.content),
                timestamp = secureMessage.timestamp,
                sessionNonce = secureMessage.sessionNonce,  // Preserve session nonce
                isOutgoing = secureMessage.isOutgoing,
                isRead = secureMessage.isRead,
                signature = secureMessage.signature,
                senderPublicKeyHash = secureMessage.senderPublicKeyHash,
                metadataSignature = "" // Will be set after creation
            )
            
            // Generate HMAC signature of metadata (excluding the signature field itself)
            val metadataToSign = buildString {
                append("message:")
                append(encryptedMessage.id)
                append(":")
                append(encryptedMessage.senderNameEncrypted)
                append(":")
                append(encryptedMessage.recipientNameEncrypted)
                append(":")
                append(encryptedMessage.contentEncrypted)
                append(":")
                append(encryptedMessage.timestamp)
                append(":")
                append(encryptedMessage.sessionNonce)  // Include session nonce in metadata
                append(":")
                append(encryptedMessage.isOutgoing)
                append(":")
                append(encryptedMessage.isRead)
                append(":")
                append(encryptedMessage.signature ?: "")
                append(":")
                append(encryptedMessage.senderPublicKeyHash ?: "")
            }
            
            return encryptedMessage.copy(
                metadataSignature = signMetadata(metadataToSign)
            )
        }
        
        fun toSecureMessage(encryptedMessage: EncryptedSecureMessage, decryptField: (String) -> String, verifyMetadata: (String, String) -> Boolean): SecureMessage {
            // Verify metadata signature before processing
            val metadataToVerify = buildString {
                append("message:")
                append(encryptedMessage.id)
                append(":")
                append(encryptedMessage.senderNameEncrypted)
                append(":")
                append(encryptedMessage.recipientNameEncrypted)
                append(":")
                append(encryptedMessage.contentEncrypted)
                append(":")
                append(encryptedMessage.timestamp)
                append(":")
                append(encryptedMessage.sessionNonce)  // Include session nonce in verification
                append(":")
                append(encryptedMessage.isOutgoing)
                append(":")
                append(encryptedMessage.isRead)
                append(":")
                append(encryptedMessage.signature ?: "")
                append(":")
                append(encryptedMessage.senderPublicKeyHash ?: "")
            }
            
            if (!verifyMetadata(metadataToVerify, encryptedMessage.metadataSignature)) {
                throw SecurityException("Metadata signature verification failed - possible tampering detected")
            }
            
            return SecureMessage(
                id = encryptedMessage.id,
                senderName = decryptField(encryptedMessage.senderNameEncrypted),
                recipientName = decryptField(encryptedMessage.recipientNameEncrypted),
                content = decryptField(encryptedMessage.contentEncrypted),
                timestamp = encryptedMessage.timestamp,
                sessionNonce = encryptedMessage.sessionNonce,  // Preserve original session nonce
                isOutgoing = encryptedMessage.isOutgoing,
                isRead = encryptedMessage.isRead,
                signature = encryptedMessage.signature,
                senderPublicKeyHash = encryptedMessage.senderPublicKeyHash
            )
        }
    }
}

/**
 * Security exception for integrity violations
 */
class DataIntegrityException(message: String, cause: Throwable? = null) : 
    SecurityException("Data integrity violation: $message", cause) {
    
    companion object {
        /**
         * Create exception for replay attack detection
         */
        fun replayAttack(objectId: String, objectType: String): DataIntegrityException {
            return DataIntegrityException("Replay attack detected on $objectType with ID: $objectId")
        }
        
        /**
         * Create exception for substitution attack detection
         */
        fun substitutionAttack(objectId: String, objectType: String): DataIntegrityException {
            return DataIntegrityException("Substitution attack detected on $objectType with ID: $objectId")
        }
        
        /**
         * Create exception for AAD verification failure
         */
        fun aadVerificationFailed(objectId: String, objectType: String, cause: Throwable? = null): DataIntegrityException {
            return DataIntegrityException("AAD verification failed for $objectType with ID: $objectId", cause)
        }
        
        /**
         * Create exception for metadata signature verification failure
         */
        fun metadataSignatureFailed(objectId: String, objectType: String, cause: Throwable? = null): DataIntegrityException {
            return DataIntegrityException("Metadata signature verification failed for $objectType with ID: $objectId", cause)
        }
    }
} 