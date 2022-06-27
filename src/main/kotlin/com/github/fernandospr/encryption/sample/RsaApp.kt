package com.github.fernandospr.encryption.sample

import com.github.fernandospr.encryption.sample.rsa.RSA
import com.github.fernandospr.encryption.sample.utils.decodeBase64
import com.github.fernandospr.encryption.sample.utils.encodeToBase64

fun main() {
    // region Key generation
    println("RSA KEY GENERATION")
    val rsa = RSA()
    val rsaPubKey = rsa.base64EncodedPublicKey
    val rsaPrvKey = rsa.base64EncodedPrivateKey
    println("PubKey (Base64): $rsaPubKey")
    println("PrvKey (Base64): $rsaPrvKey")
    println()
    // endregion

    // region Encrypt
    println("RSA ENCRYPTION")
    val rsaPubEncryptKey = rsaPubKey
    val message = "Hello world!"
    println("PubKey (Base64): $rsaPubEncryptKey")
    println("Message: $message")
    val encrypted = RSA.encrypt(message.toByteArray(), rsaPubEncryptKey)
    val encryptedMessage = encrypted.encodeToBase64()
    println("Encrypted message (Base64): $encryptedMessage")
    println()
    // endregion

    // region Decrypt
    println("RSA DECRYPTION")
    val rsaPrvDecryptKey = rsaPrvKey
    val encryptedMessageToDecrypt = encryptedMessage
    println("PrvKey (Base64): $rsaPrvDecryptKey")
    println("Encrypted message (Base64): $encryptedMessageToDecrypt")
    val decrypted = RSA.decrypt(encryptedMessageToDecrypt.decodeBase64(), rsaPrvDecryptKey)
    val decryptedMessage = decrypted.toString(Charsets.UTF_8)
    println("Decrypted message: $decryptedMessage")
    println()
    // endregion

    // region Sign
    println("RSA SIGNATURE")
    val rsaPrvSignKey = rsaPrvKey
    val messageToSign = decryptedMessage
    println("PrvKey (Base64): $rsaPrvSignKey")
    println("Message (Base64): $messageToSign")
    val signature = RSA.sign(messageToSign.toByteArray(), rsaPrvSignKey)
    val signatureBase64 = signature.encodeToBase64()
    println("Signature (Base64): $signatureBase64")
    println()
    // endregion

    // region Verify Signature
    println("RSA SIGNATURE VERIFICATION")
    val rsaPubSignVerifKey = rsaPubKey
    val messageToVerify = messageToSign
    val signatureToVerify = signatureBase64
    println("PubKey (Base64): $rsaPubSignVerifKey")
    println("Message: $messageToSign")
    println("Signature (Base64): $signatureToVerify")
    val verification = RSA.verify(signatureToVerify.decodeBase64(), messageToVerify.toByteArray(), rsaPubSignVerifKey)
    println("Valid Signature: $verification")
    println()
    // endregion
}