package com.qrypteye.app.crypto

import android.util.Base64
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

class CryptoManager {
    
    companion object {
        private const val RSA_KEY_SIZE = 2048
        private const val AES_KEY_SIZE = 256
        private const val AES_ALGORITHM = "AES/CBC/PKCS5Padding"
        private const val RSA_ALGORITHM = "RSA/ECB/PKCS1Padding"
        private const val SIGNATURE_ALGORITHM = "SHA256withRSA"
        
        init {
            Security.addProvider(BouncyCastleProvider())
        }
    }
    
    /**
     * Generate a new RSA key pair
     */
    fun generateKeyPair(): KeyPair {
        val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
        keyPairGenerator.initialize(RSA_KEY_SIZE, SecureRandom())
        return keyPairGenerator.generateKeyPair()
    }
    
    /**
     * Encrypt a message using hybrid encryption (AES + RSA)
     */
    fun encryptMessage(message: String, recipientPublicKey: PublicKey): EncryptedMessage {
        // Generate a random AES key
        val aesKey = generateAESKey()
        
        // Encrypt the message with AES
        val encryptedData = encryptWithAES(message.toByteArray(), aesKey)
        
        // Encrypt the AES key with recipient's RSA public key
        val encryptedAESKey = encryptWithRSA(aesKey.encoded, recipientPublicKey)
        
        return EncryptedMessage(
            encryptedData = Base64.encodeToString(encryptedData.encryptedBytes, Base64.DEFAULT),
            encryptedKey = Base64.encodeToString(encryptedAESKey, Base64.DEFAULT),
            iv = Base64.encodeToString(encryptedData.iv, Base64.DEFAULT),
            timestamp = System.currentTimeMillis()
        )
    }
    
    /**
     * Decrypt a message using hybrid decryption
     */
    fun decryptMessage(encryptedMessage: EncryptedMessage, privateKey: PrivateKey): String {
        // Decrypt the AES key with our RSA private key
        val encryptedAESKeyBytes = Base64.decode(encryptedMessage.encryptedKey, Base64.DEFAULT)
        val aesKeyBytes = decryptWithRSA(encryptedAESKeyBytes, privateKey)
        val aesKey = SecretKeySpec(aesKeyBytes, "AES")
        
        // Decrypt the message with AES
        val encryptedDataBytes = Base64.decode(encryptedMessage.encryptedData, Base64.DEFAULT)
        val ivBytes = Base64.decode(encryptedMessage.iv, Base64.DEFAULT)
        val decryptedBytes = decryptWithAES(encryptedDataBytes, aesKey, ivBytes)
        
        return String(decryptedBytes)
    }
    
    /**
     * Sign data with private key
     */
    fun signData(data: String, privateKey: PrivateKey): String {
        val signature = Signature.getInstance(SIGNATURE_ALGORITHM)
        signature.initSign(privateKey)
        signature.update(data.toByteArray())
        return Base64.encodeToString(signature.sign(), Base64.DEFAULT)
    }
    
    /**
     * Verify signature with public key
     */
    fun verifySignature(data: String, signature: String, publicKey: PublicKey): Boolean {
        return try {
            val sig = Signature.getInstance(SIGNATURE_ALGORITHM)
            sig.initVerify(publicKey)
            sig.update(data.toByteArray())
            sig.verify(Base64.decode(signature, Base64.DEFAULT))
        } catch (e: Exception) {
            false
        }
    }
    
    /**
     * Create a signed encrypted message
     */
    fun createSignedEncryptedMessage(
        message: String, 
        recipientPublicKey: PublicKey, 
        senderPrivateKey: PrivateKey
    ): SignedEncryptedMessage {
        val encryptedMessage = encryptMessage(message, recipientPublicKey)
        val messageData = "${encryptedMessage.encryptedData}${encryptedMessage.encryptedKey}${encryptedMessage.iv}${encryptedMessage.timestamp}"
        val signature = signData(messageData, senderPrivateKey)
        
        return SignedEncryptedMessage(
            encryptedMessage = encryptedMessage,
            signature = signature
        )
    }
    
    /**
     * Verify and decrypt a signed message
     */
    fun verifyAndDecryptMessage(
        signedMessage: SignedEncryptedMessage,
        senderPublicKey: PublicKey,
        recipientPrivateKey: PrivateKey
    ): VerificationResult {
        val encryptedMessage = signedMessage.encryptedMessage
        val messageData = "${encryptedMessage.encryptedData}${encryptedMessage.encryptedKey}${encryptedMessage.iv}${encryptedMessage.timestamp}"
        
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
     */
    fun exportPublicKey(publicKey: PublicKey): String {
        return Base64.encodeToString(publicKey.encoded, Base64.DEFAULT)
    }
    
    /**
     * Export private key to string format
     */
    fun exportPrivateKey(privateKey: PrivateKey): String {
        return Base64.encodeToString(privateKey.encoded, Base64.DEFAULT)
    }
    
    /**
     * Import public key from string format
     */
    fun importPublicKey(publicKeyString: String): PublicKey {
        val keyBytes = Base64.decode(publicKeyString, Base64.DEFAULT)
        val keySpec = X509EncodedKeySpec(keyBytes)
        val keyFactory = KeyFactory.getInstance("RSA")
        return keyFactory.generatePublic(keySpec)
    }
    
    /**
     * Import private key from string format
     */
    fun importPrivateKey(privateKeyString: String): PrivateKey {
        val keyBytes = Base64.decode(privateKeyString, Base64.DEFAULT)
        val keySpec = PKCS8EncodedKeySpec(keyBytes)
        val keyFactory = KeyFactory.getInstance("RSA")
        return keyFactory.generatePrivate(keySpec)
    }
    
    private fun generateAESKey(): SecretKey {
        val keyGenerator = KeyGenerator.getInstance("AES")
        keyGenerator.init(AES_KEY_SIZE)
        return keyGenerator.generateKey()
    }
    
    private fun encryptWithAES(data: ByteArray, key: SecretKey): AESEncryptedData {
        val cipher = Cipher.getInstance(AES_ALGORITHM)
        cipher.init(Cipher.ENCRYPT_MODE, key)
        val encryptedBytes = cipher.doFinal(data)
        val iv = cipher.iv
        return AESEncryptedData(encryptedBytes, iv)
    }
    
    private fun decryptWithAES(encryptedData: ByteArray, key: SecretKey, iv: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(AES_ALGORITHM)
        val ivSpec = IvParameterSpec(iv)
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec)
        return cipher.doFinal(encryptedData)
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
    
    data class AESEncryptedData(val encryptedBytes: ByteArray, val iv: ByteArray)
    
    data class EncryptedMessage(
        val encryptedData: String,
        val encryptedKey: String,
        val iv: String,
        val timestamp: Long
    )
    
    data class SignedEncryptedMessage(
        val encryptedMessage: EncryptedMessage,
        val signature: String
    )
    
    sealed class VerificationResult {
        data class Success(val message: String) : VerificationResult()
        object AuthenticationFailed : VerificationResult()
        data class DecryptionFailed(val error: String) : VerificationResult()
    }
} 