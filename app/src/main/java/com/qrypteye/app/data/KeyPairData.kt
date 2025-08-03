package com.qrypteye.app.data

import java.security.KeyPair

data class KeyPairData(
    val id: String = java.util.UUID.randomUUID().toString(),
    val keyPair: KeyPair,
    val publicKeyString: String,
    val privateKeyString: String,
    val timestamp: Long = System.currentTimeMillis()
) {
    companion object {
        fun create(keyPair: KeyPair): KeyPairData {
            val cryptoManager = com.qrypteye.app.crypto.CryptoManager()
            return KeyPairData(
                keyPair = keyPair,
                publicKeyString = cryptoManager.exportPublicKey(keyPair.public),
                privateKeyString = cryptoManager.exportPrivateKey(keyPair.private)
            )
        }
    }
} 