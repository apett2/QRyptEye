package com.qrypteye.app.crypto

import android.util.Base64
import com.google.gson.Gson
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.*
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec
import javax.crypto.spec.IvParameterSpec
import java.util.*

/**
 * SECURITY CRITICAL COMPONENT
 * 
 * This class handles all cryptographic operations for QRyptEye.
 * 
 * SECURITY REQUIREMENTS:
 * 1. ALL keys MUST be generated using cryptographically secure random number generators (SecureRandom)
 * 2. NEVER derive keys from passwords without proper Key Derivation Functions (KDF)
 * 3. NEVER reuse keys across different messages or sessions
 * 4. NEVER store keys in plain text or weak storage
 * 5. ALL cryptographic operations MUST use secure algorithms and parameters
 * 6. ALL signatures MUST use canonical JSON context to prevent ambiguity attacks
 * 
 * KEY DERIVATION WARNING:
 * If you ever need to derive keys from passwords (NOT RECOMMENDED for this application):
 * - Use PBKDF2 with at least 100,000 iterations
 * - Use scrypt with N=16384, r=8, p=1 minimum
 * - Use Argon2 with appropriate parameters
 * - Always use a salt of at least 16 bytes
 * - Never use weak entropy sources (Math.random(), timestamps, etc.)
 * 
 * SIGNATURE SECURITY:
 * - Uses canonical JSON serialization for signature context
 * - Prevents string concatenation ambiguity attacks
 * - Ensures unambiguous field separation in signed data
 * 
 * This implementation is designed for air-gapped secure messaging and uses
 * cryptographically secure random key generation for maximum security.
 */
class CryptoManager {
    
    companion object {
        private const val RSA_KEY_SIZE = 2048
        private const val AES_KEY_SIZE = 256
        // SECURITY: Using GCM for authenticated encryption to prevent tampering attacks
        // GCM provides both confidentiality and integrity in a single operation
        private const val AES_ALGORITHM = "AES/GCM/NoPadding"
        // SECURITY: Using OAEP padding to prevent padding oracle attacks
        // OAEPWithSHA-256AndMGF1Padding provides semantic security and is resistant to chosen-ciphertext attacks
        private const val RSA_ALGORITHM = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"
        private const val SIGNATURE_ALGORITHM = "SHA256withRSA"
        private const val GCM_IV_LENGTH = 12  // 96 bits for GCM
        private const val GCM_TAG_LENGTH = 16 // 128 bits for authentication tag
        
        // SECURITY: Replay attack protection constants
        private const val MAX_MESSAGE_AGE_MS = 24 * 60 * 60 * 1000L // 24 hours
        private const val MAX_FUTURE_TIME_MS = 5 * 60 * 1000L // 5 minutes (clock skew allowance)
        
        // Base64 encoding flags for consistency and security
        private const val BASE64_FLAGS = Base64.NO_WRAP or Base64.URL_SAFE
        
        // Size limits for encrypted data
        private const val MAX_ENCRYPTED_MESSAGE_SIZE = 512 * 1024 // 512KB
        private const val MAX_SIGNATURE_SIZE = 1024 // 1KB
        
        // Use canonical Gson for cryptographic operations
        private val canonicalGson = com.qrypteye.app.data.CanonicalGson.instance
        
        init {
            Security.addProvider(BouncyCastleProvider())
        }
    }
    
    /**
     * Data class for signature context to prevent ambiguity attacks
     * 
     * SECURITY: This ensures unambiguous serialization of data to be signed.
     * Using canonical JSON prevents string concatenation attacks where malicious
     * data could create the same signature as legitimate data.
     */
    private data class SignatureContext(
        val encryptedData: String,
        val encryptedKey: String,
        val iv: String,
        val authTag: String,
        val timestamp: Long
    )
    
    /**
     * Validate message timestamp to prevent replay attacks
     * 
     * SECURITY: This method prevents replay attacks by ensuring messages are:
     * 1. Not too old (within 24 hours)
     * 2. Not from the future (allowing 5 minutes for clock skew)
     * 3. Fresh enough to be considered valid
     * 
     * @param timestamp The message timestamp to validate
     * @return true if the message is fresh and valid, false otherwise
     */
    private fun isMessageFresh(timestamp: Long): Boolean {
        val currentTime = System.currentTimeMillis()
        
        // Check if message is too old (replay attack protection)
        if (currentTime - timestamp > MAX_MESSAGE_AGE_MS) {
            return false
        }
        
        // Check if message is from the future (clock skew protection)
        if (timestamp - currentTime > MAX_FUTURE_TIME_MS) {
            return false
        }
        
        return true
    }
    
    /**
     * Create canonical JSON string for signature context
     * 
     * SECURITY: This method creates unambiguous serialization to prevent
     * signature ambiguity attacks. The JSON format ensures proper field separation
     * and prevents malicious data injection through string concatenation.
     */
    private fun createSignatureContext(encryptedMessage: EncryptedMessage): String {
        val context = SignatureContext(
            encryptedData = encryptedMessage.encryptedData,
            encryptedKey = encryptedMessage.encryptedKey,
            iv = encryptedMessage.iv,
            authTag = encryptedMessage.authTag,
            timestamp = encryptedMessage.timestamp
        )
        return canonicalGson.toJson(context)
    }
    
    /**
     * Generate a new RSA key pair
     * 
     * SECURITY: This method uses SecureRandom for key generation.
     * NEVER derive keys from passwords or user input without proper KDF (PBKDF2, scrypt, Argon2).
     * Password-derived keys without KDF are vulnerable to brute force attacks.
     */
    fun generateKeyPair(): KeyPair {
        val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
        keyPairGenerator.initialize(RSA_KEY_SIZE, SecureRandom())
        return keyPairGenerator.generateKeyPair()
    }
    
    /**
     * Encrypt a message using hybrid encryption
     */
    fun encryptMessage(message: String, recipientPublicKey: PublicKey): EncryptedMessage {
        // Generate a random AES key
        val keyGenerator = KeyGenerator.getInstance("AES")
        keyGenerator.init(AES_KEY_SIZE)
        val aesKey = keyGenerator.generateKey()
        
        // Encrypt the message with AES
        val encryptedData = encryptWithAES(message.toByteArray(), aesKey)
        
        // Encrypt the AES key with recipient's RSA public key
        val encryptedAESKey = encryptWithRSA(aesKey.encoded, recipientPublicKey)
        
        val encryptedMessage = EncryptedMessage(
            encryptedData = Base64.encodeToString(encryptedData.encryptedBytes, BASE64_FLAGS),
            encryptedKey = Base64.encodeToString(encryptedAESKey, BASE64_FLAGS),
            iv = Base64.encodeToString(encryptedData.iv, BASE64_FLAGS),
            authTag = Base64.encodeToString(encryptedData.authTag, BASE64_FLAGS),
            timestamp = System.currentTimeMillis()
        )
        
        // Validate encrypted message size
        val totalSize = encryptedMessage.encryptedData.length + 
                       encryptedMessage.encryptedKey.length + 
                       encryptedMessage.iv.length + 
                       encryptedMessage.authTag.length
        
        if (totalSize > MAX_ENCRYPTED_MESSAGE_SIZE) {
            throw SecurityException("Encrypted message exceeds size limit")
        }
        
        return encryptedMessage
    }
    
    /**
     * Decrypt a message using hybrid decryption
     */
    fun decryptMessage(encryptedMessage: EncryptedMessage, privateKey: PrivateKey): String {
        // Validate encrypted message size
        val totalSize = encryptedMessage.encryptedData.length + 
                       encryptedMessage.encryptedKey.length + 
                       encryptedMessage.iv.length + 
                       encryptedMessage.authTag.length
        
        if (totalSize > MAX_ENCRYPTED_MESSAGE_SIZE) {
            throw SecurityException("Encrypted message exceeds size limit")
        }
        
        // Decrypt the AES key with our RSA private key
        val encryptedAESKeyBytes = Base64.decode(encryptedMessage.encryptedKey, BASE64_FLAGS)
        val aesKeyBytes = decryptWithRSA(encryptedAESKeyBytes, privateKey)
        val aesKey = SecretKeySpec(aesKeyBytes, "AES")
        
        // Decrypt the message with AES
        val encryptedDataBytes = Base64.decode(encryptedMessage.encryptedData, BASE64_FLAGS)
        val ivBytes = Base64.decode(encryptedMessage.iv, BASE64_FLAGS)
        val authTagBytes = Base64.decode(encryptedMessage.authTag, BASE64_FLAGS)
        val decryptedBytes = decryptWithAES(encryptedDataBytes, aesKey, ivBytes, authTagBytes)
        
        return String(decryptedBytes)
    }
    
    /**
     * Sign data with private key
     */
    fun signData(data: String, privateKey: PrivateKey): String {
        val signature = Signature.getInstance(SIGNATURE_ALGORITHM)
        signature.initSign(privateKey)
        signature.update(data.toByteArray())
        val signatureBytes = signature.sign()
        val signatureString = Base64.encodeToString(signatureBytes, BASE64_FLAGS)
        
        // Validate signature size
        if (signatureString.length > MAX_SIGNATURE_SIZE) {
            throw SecurityException("Generated signature exceeds size limit")
        }
        
        return signatureString
    }
    
    /**
     * Verify signature with public key
     */
    fun verifySignature(data: String, signature: String, publicKey: PublicKey): Boolean {
        return try {
            // Validate signature size
            if (signature.length > MAX_SIGNATURE_SIZE) {
                return false
            }
            
            val sig = Signature.getInstance(SIGNATURE_ALGORITHM)
            sig.initVerify(publicKey)
            sig.update(data.toByteArray())
            sig.verify(Base64.decode(signature, BASE64_FLAGS))
        } catch (e: Exception) {
            false
        }
    }
    
    /**
     * Create a signed encrypted message
     * 
     * SECURITY: Uses canonical JSON for signature context to prevent ambiguity attacks.
     * This ensures that malicious data cannot create the same signature as legitimate data
     * through string concatenation manipulation.
     */
    fun createSignedEncryptedMessage(
        message: String, 
        recipientPublicKey: PublicKey, 
        senderPrivateKey: PrivateKey
    ): SignedEncryptedMessage {
        val encryptedMessage = encryptMessage(message, recipientPublicKey)
        
        // Create canonical JSON signature context to prevent ambiguity attacks
        val messageData = createSignatureContext(encryptedMessage)
        val signature = signData(messageData, senderPrivateKey)
        
        return SignedEncryptedMessage(
            encryptedMessage = encryptedMessage,
            signature = signature
        )
    }
    
    /**
     * Verify and decrypt a signed message
     * 
     * SECURITY: Uses canonical JSON for signature context to prevent ambiguity attacks.
     * This ensures that malicious data cannot create the same signature as legitimate data
     * through string concatenation manipulation.
     * 
     * SECURITY: Includes replay attack protection by validating message freshness.
     * Messages older than 24 hours or from the future are rejected.
     */
    fun verifyAndDecryptMessage(
        signedMessage: SignedEncryptedMessage,
        senderPublicKey: PublicKey,
        recipientPrivateKey: PrivateKey
    ): VerificationResult {
        val encryptedMessage = signedMessage.encryptedMessage
        
        // SECURITY: Check for replay attacks before signature verification
        if (!isMessageFresh(encryptedMessage.timestamp)) {
            return VerificationResult.ReplayAttack
        }
        
        // Create canonical JSON signature context to prevent ambiguity attacks
        val messageData = createSignatureContext(encryptedMessage)
        
        // Verify signature
        val isAuthentic = verifySignature(messageData, signedMessage.signature, senderPublicKey)
        
        if (!isAuthentic) {
            return VerificationResult.AuthenticationFailed
        }
        
        // Decrypt message
        return try {
            val decryptedMessage = decryptMessage(encryptedMessage, recipientPrivateKey)
            VerificationResult.Success(decryptedMessage)
        } catch (e: Exception) {
            VerificationResult.DecryptionFailed(e.message ?: "Unknown error")
        }
    }
    
    /**
     * Export public key to string format
     * 
     * SECURITY: Uses URL_SAFE and NO_WRAP flags to prevent newline artifacts
     * and ensure cross-platform compatibility.
     */
    fun exportPublicKey(publicKey: PublicKey): String {
        return Base64.encodeToString(publicKey.encoded, BASE64_FLAGS)
    }
    
    /**
     * Export private key to string format
     * 
     * SECURITY: Uses URL_SAFE and NO_WRAP flags to prevent newline artifacts
     * and ensure cross-platform compatibility.
     */
    fun exportPrivateKey(privateKey: PrivateKey): String {
        return Base64.encodeToString(privateKey.encoded, BASE64_FLAGS)
    }
    
    /**
     * Import public key from string format
     * 
     * SECURITY: Uses URL_SAFE and NO_WRAP flags to prevent newline artifacts
     * and ensure cross-platform compatibility.
     */
    fun importPublicKey(publicKeyString: String): PublicKey {
        val keyBytes = Base64.decode(publicKeyString, BASE64_FLAGS)
        val keySpec = X509EncodedKeySpec(keyBytes)
        val keyFactory = KeyFactory.getInstance("RSA")
        return keyFactory.generatePublic(keySpec)
    }
    
    /**
     * Import private key from string format
     * 
     * SECURITY: Uses URL_SAFE and NO_WRAP flags to prevent newline artifacts
     * and ensure cross-platform compatibility.
     */
    fun importPrivateKey(privateKeyString: String): PrivateKey {
        val keyBytes = Base64.decode(privateKeyString, BASE64_FLAGS)
        val keySpec = PKCS8EncodedKeySpec(keyBytes)
        val keyFactory = KeyFactory.getInstance("RSA")
        return keyFactory.generatePrivate(keySpec)
    }
    
    /**
     * Generate a cryptographically secure AES key
     * 
     * SECURITY CRITICAL: This method MUST ONLY use SecureRandom or equivalent cryptographically secure RNG.
     * 
     * DO NOT:
     * - Derive keys from passwords without proper KDF (PBKDF2, scrypt, Argon2)
     * - Use weak entropy sources (Math.random(), System.currentTimeMillis(), etc.)
     * - Reuse keys across different messages or sessions
     * - Store keys in plain text or weak storage
     * 
     * Key derivation from passwords requires:
     * - PBKDF2 with at least 100,000 iterations
     * - scrypt with appropriate parameters (N=16384, r=8, p=1 minimum)
     * - Argon2 with appropriate parameters
     * - Salt of at least 16 bytes
     * 
     * This implementation uses SecureRandom for maximum security.
     */
    private fun generateAESKey(): SecretKey {
        val keyGenerator = KeyGenerator.getInstance("AES")
        keyGenerator.init(AES_KEY_SIZE, SecureRandom())
        return keyGenerator.generateKey()
    }
    
    private fun encryptWithAES(data: ByteArray, key: SecretKey): AESEncryptedData {
        val cipher = Cipher.getInstance(AES_ALGORITHM)
        cipher.init(Cipher.ENCRYPT_MODE, key)
        val encryptedBytes = cipher.doFinal(data)
        val iv = cipher.iv
        
        // For GCM, the authentication tag is appended to the encrypted data
        // We need to separate the ciphertext from the authentication tag
        val ciphertextLength = encryptedBytes.size - GCM_TAG_LENGTH
        val ciphertext = encryptedBytes.copyOfRange(0, ciphertextLength)
        val authTag = encryptedBytes.copyOfRange(ciphertextLength, encryptedBytes.size)
        
        return AESEncryptedData(ciphertext, iv, authTag)
    }
    
    private fun decryptWithAES(encryptedData: ByteArray, key: SecretKey, iv: ByteArray, authTag: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(AES_ALGORITHM)
        val ivSpec = IvParameterSpec(iv)
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec)
        
        // Combine ciphertext and authentication tag for GCM decryption
        val combinedData = encryptedData + authTag
        return cipher.doFinal(combinedData)
    }
    
    private fun encryptWithRSA(data: ByteArray, publicKey: PublicKey): ByteArray {
        val cipher = Cipher.getInstance(RSA_ALGORITHM)
        cipher.init(Cipher.ENCRYPT_MODE, publicKey)
        return cipher.doFinal(data)
    }
    
    private fun decryptWithRSA(encryptedData: ByteArray, privateKey: PrivateKey): ByteArray {
        val cipher = Cipher.getInstance(RSA_ALGORITHM)
        cipher.init(Cipher.DECRYPT_MODE, privateKey)
        return cipher.doFinal(encryptedData)
    }
    
    data class AESEncryptedData(
        val encryptedBytes: ByteArray, 
        val iv: ByteArray,
        val authTag: ByteArray  // GCM authentication tag for integrity verification
    )
    
    data class EncryptedMessage(
        val encryptedData: String,
        val encryptedKey: String,
        val iv: String,
        val authTag: String,  // GCM authentication tag for integrity verification
        val timestamp: Long
    )
    
    data class SignedEncryptedMessage(
        val encryptedMessage: EncryptedMessage,
        val signature: String
    )
    
    sealed class VerificationResult {
        data class Success(val message: String) : VerificationResult()
        object AuthenticationFailed : VerificationResult()
        object ReplayAttack : VerificationResult()  // New: Replay attack detected
        data class DecryptionFailed(val error: String) : VerificationResult()
    }
} 