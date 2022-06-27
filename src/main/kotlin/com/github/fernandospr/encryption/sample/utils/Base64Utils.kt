package com.github.fernandospr.encryption.sample.utils

import java.util.*

fun ByteArray.encodeToBase64() = Base64.getEncoder().encodeToString(this)

fun String.decodeBase64() = Base64.getDecoder().decode(this)