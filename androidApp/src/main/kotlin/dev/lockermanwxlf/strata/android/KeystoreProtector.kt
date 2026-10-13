package dev.lockermanwxlf.strata.android

import android.app.Activity
import android.app.KeyguardManager
import android.hardware.biometrics.BiometricManager.Authenticators.BIOMETRIC_STRONG
import android.hardware.biometrics.BiometricManager.Authenticators.DEVICE_CREDENTIAL
import android.hardware.biometrics.BiometricPrompt
import android.os.Build
import android.os.CancellationSignal
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.util.Log
import dev.lockermanwxlf.strata.core.ffi.PlatformProtector
import dev.lockermanwxlf.strata.core.ffi.ProtectorCaps
import dev.lockermanwxlf.strata.core.ffi.ProtectorException
import java.security.KeyStore
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext

/**
 * Android Keystore as a platform protector (CLAUDE.md "Platform protectors"): one
 * AES-256-GCM key for the app, in StrongBox when the device has it and the TEE
 * otherwise, usable only right after the user authenticates. Each slot's secret is
 * encrypted with the slot ID as associated data. A biometric enrollment change
 * invalidates the key, which the core treats as "slot gone".
 */
class KeystoreProtector(private val activity: Activity) : PlatformProtector {
    private val keyStore = KeyStore.getInstance(STORE).apply { load(null) }

    /** Device unlock needs a screen lock; without one there's nothing to offer. */
    val available: Boolean
        get() = activity.getSystemService(KeyguardManager::class.java).isDeviceSecure

    override fun capabilities(): ProtectorCaps {
        // Reported from the key as created, never assumed: StrongBox can be missing.
        val hardware = runCatching { isHardwareBacked(key(create = true)!!) }
            .onFailure { Log.w(TAG, "couldn't create or inspect the device-unlock key", it) }
            .getOrDefault(false)
        // Hardware-backed keys sit behind Gatekeeper/biometric lockout, enforced in the TEE.
        return ProtectorCaps(hardwareBacked = hardware, rateLimited = hardware, userPresence = true)
    }

    override suspend fun wrap(slotId: String, secret: ByteArray): ByteArray {
        try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.ENCRYPT_MODE, key(create = true))
            val authorized = authenticate(cipher, "Turn on device unlock for Strata")
            authorized.updateAAD(slotId.encodeToByteArray())
            return authorized.iv + authorized.doFinal(secret)
        } catch (e: KeyPermanentlyInvalidatedException) {
            // Enrollment changed since the key was made: start over with a fresh key.
            keyStore.deleteEntry(ALIAS)
            throw ProtectorException.KeyInvalidated()
        } finally {
            secret.fill(0)
        }
    }

    override suspend fun unwrap(slotId: String, blob: ByteArray): ByteArray {
        val key = key(create = false) ?: throw ProtectorException.KeyInvalidated()
        if (blob.size <= IV_LEN) throw ProtectorException.KeyInvalidated()
        val cipher = Cipher.getInstance(TRANSFORMATION)
        try {
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, blob, 0, IV_LEN))
        } catch (e: KeyPermanentlyInvalidatedException) {
            keyStore.deleteEntry(ALIAS)
            throw ProtectorException.KeyInvalidated()
        }
        val authorized = authenticate(cipher, "Unlock Strata")
        authorized.updateAAD(slotId.encodeToByteArray())
        return try {
            authorized.doFinal(blob, IV_LEN, blob.size - IV_LEN)
        } catch (e: AEADBadTagException) {
            throw ProtectorException.KeyInvalidated()
        }
    }

    /** The key is shared by every slot, so removing one slot leaves it. */
    override fun delete(slotId: String) = Unit

    private fun key(create: Boolean): SecretKey? {
        (keyStore.getKey(ALIAS, null) as? SecretKey)?.let { return it }
        if (!create) return null
        return try {
            generate(strongBox = true)
        } catch (e: StrongBoxUnavailableException) {
            generate(strongBox = false)
        }
    }

    private fun generate(strongBox: Boolean): SecretKey {
        val spec = KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setUserAuthenticationRequired(true)
            .setInvalidatedByBiometricEnrollment(true)
            .setIsStrongBoxBacked(strongBox)
            .apply {
                // Every use needs a fresh authentication: biometrics, or (API 30+) the screen lock.
                if (Build.VERSION.SDK_INT >= 30) setUserAuthenticationParameters(0, BIOMETRIC_STRONG or DEVICE_CREDENTIAL)
            }
            .build()
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, STORE).run {
            init(spec)
            generateKey()
        }
    }

    private fun isHardwareBacked(key: SecretKey): Boolean {
        val info = SecretKeyFactory.getInstance(key.algorithm, STORE).getKeySpec(key, KeyInfo::class.java) as KeyInfo
        if (Build.VERSION.SDK_INT >= 31) Log.i(TAG, "device-unlock key security level: ${info.securityLevel}")
        return if (Build.VERSION.SDK_INT >= 31) {
            info.securityLevel == KeyProperties.SECURITY_LEVEL_STRONGBOX ||
                info.securityLevel == KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT
        } else {
            @Suppress("DEPRECATION")
            info.isInsideSecureHardware
        }
    }

    /** Shows the system prompt bound to [cipher]; returns it authorized for one use. */
    private suspend fun authenticate(cipher: Cipher, title: String): Cipher = withContext(Dispatchers.Main) {
        suspendCancellableCoroutine { cont ->
            val signal = CancellationSignal()
            cont.invokeOnCancellation { signal.cancel() }
            val prompt = BiometricPrompt.Builder(activity).setTitle(title).apply {
                if (Build.VERSION.SDK_INT >= 30) {
                    setAllowedAuthenticators(BIOMETRIC_STRONG or DEVICE_CREDENTIAL)
                } else {
                    // Before API 30 a crypto-bound prompt takes biometrics only.
                    setNegativeButton("Cancel", activity.mainExecutor) { _, _ ->
                        if (cont.isActive) cont.resumeWithException(ProtectorException.Cancelled())
                    }
                }
            }.build()
            prompt.authenticate(
                BiometricPrompt.CryptoObject(cipher),
                signal,
                activity.mainExecutor,
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                        val authorized = result.cryptoObject?.cipher
                        if (authorized == null) {
                            cont.resumeWithException(ProtectorException.Platform("no cipher after authentication"))
                        } else {
                            cont.resume(authorized)
                        }
                    }

                    override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                        if (!cont.isActive) return
                        val cancelled = errorCode == BiometricPrompt.BIOMETRIC_ERROR_USER_CANCELED ||
                            errorCode == BiometricPrompt.BIOMETRIC_ERROR_CANCELED
                        cont.resumeWithException(
                            if (cancelled) ProtectorException.Cancelled() else ProtectorException.Unavailable(errString.toString()),
                        )
                    }
                    // onAuthenticationFailed: a finger that didn't match; the prompt stays up.
                },
            )
        }
    }

    private companion object {
        const val TAG = "Strata"
        const val STORE = "AndroidKeyStore"
        const val ALIAS = "strata-device-unlock"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val IV_LEN = 12
    }
}
