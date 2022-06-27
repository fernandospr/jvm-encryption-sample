package com.github.fernandospr.encryption.sample

import com.github.fernandospr.encryption.sample.aes.AES
import com.github.fernandospr.encryption.sample.utils.decodeBase64
import com.github.fernandospr.encryption.sample.utils.encodeToBase64

fun main() {
    // region Key generation
    println("AES KEY GENERATION")
    val aes = AES()
    val aesKey = aes.base64EncodedKey
    val aesIv = aes.base64EncodedIv
    println("Key (Base64): $aesKey")
    println("IV (Base64): $aesIv")
    println()
    // endregion

    // region Encrypt
    println("AES ENCRYPTION")
    val aesEncryptKey = aesKey
    val aesEncryptIv = aesIv // Optional
    val message = "Hello world!"
    println("Key (Base64): $aesEncryptKey")
    println("IV (Base64) - Optional: $aesEncryptIv")
    println("Message: $message")
    val encrypted = AES.encrypt(message.toByteArray(), aesEncryptKey, aesEncryptIv)
    val encryptedMessage = encrypted.data.encodeToBase64()
    val associatedIv = encrypted.iv.encodeToBase64() // Should be the same as aesEncryptIv or should create one if aesEncryptIv is missing
    println("Encrypted message (Base64): $encryptedMessage")
    println("IV (Base64): $associatedIv")
    println()
    // endregion

    // region Decrypt
    println("AES DECRYPTION")
    val aesDecryptKey = aesKey
    val aesDecryptIv = associatedIv
    val encryptedMessageToDecrypt = encryptedMessage
    println("Key (Base64): $aesDecryptKey")
    println("IV (Base64): $aesDecryptIv")
    println("Encrypted message (Base64): $encryptedMessageToDecrypt")
    val decrypted = AES.decrypt(encryptedMessageToDecrypt.decodeBase64(), aesDecryptKey, aesDecryptIv)
    val decryptedMessage = decrypted.toString(Charsets.UTF_8)
    println("Decrypted message: $decryptedMessage")
    println()
    // endregion
}