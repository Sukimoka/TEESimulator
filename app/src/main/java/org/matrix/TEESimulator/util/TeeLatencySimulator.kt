package org.matrix.TEESimulator.util

import android.hardware.security.keymint.Algorithm
import java.security.SecureRandom
import java.util.concurrent.locks.LockSupport
import kotlin.math.exp
import kotlin.math.ln
import kotlin.math.max

/**
 * Simulates realistic TEE hardware latency for software key generation. Real TEE key generation
 * involves hardware crypto operations, TrustZone world-switching, and binder IPC overhead that
 * produce characteristic timing distributions. This simulator models those delays using
 * statistical distributions derived from observed QTEE and Trustonic hardware profiles.
 *
 * The delay is composed of three independent components:
 * 1. Base crypto processing time (log-normal, algorithm-dependent)
 * 2. Kernel/binder transit noise (exponential, models IPC jitter)
 * 3. TEE scheduler jitter (Gaussian, models world-switch variance)
 *
 * A per-boot session bias prevents cross-session fingerprinting.
 */
object TeeLatencySimulator {

    private val rng = SecureRandom()

    // Per-boot bias shifts the entire distribution to model manufacturing variance.
    private val sessionBiasMs: Double by lazy { rng.nextGaussian() * 8.0 }

    /**
     * Pads the current thread to simulate realistic TEE generateKey latency.
     *
     * @param algorithm The KeyMint algorithm constant (EC, RSA, AES, HMAC).
     * @param elapsedNanos Wall time already spent on the actual software key generation.
     */
    fun simulateGenerateKeyDelay(algorithm: Int, elapsedNanos: Long) {
        val elapsedMs = elapsedNanos / 1_000_000.0
        val targetMs = sampleTotalDelay(algorithm)
        val remainingMs = targetMs - elapsedMs

        if (remainingMs > 1.0) {
            LockSupport.parkNanos((remainingMs * 1_000_000).toLong())
        }
    }

    private fun sampleTotalDelay(algorithm: Int): Double {
        val base = sampleBaseCryptoDelay(algorithm)
        val transit = sampleExponential(5.0)
        val jitter = (rng.nextGaussian() * 3.0).coerceIn(-8.0, 15.0)
        return max(15.0, base + transit + jitter + sessionBiasMs)
    }

    /**
     * Base crypto delay models the hardware processing time. Log-normal distribution produces
     * the characteristic positive skew observed in real TEE measurements: most operations
     * cluster around the median, with occasional slower outliers.
     */
    private fun sampleBaseCryptoDelay(algorithm: Int): Double {
        val (mu, sigma) =
            when (algorithm) {
                Algorithm.EC -> ln(45.0) to 0.20
                Algorithm.RSA -> ln(55.0) to 0.22
                Algorithm.AES -> ln(30.0) to 0.15
                else -> ln(35.0) to 0.18 // HMAC, others
            }
        return sampleLogNormal(mu, sigma)
    }

    /** Log-normal sample via inverse CDF transform of Gaussian. */
    private fun sampleLogNormal(mu: Double, sigma: Double): Double {
        return exp(mu + sigma * rng.nextGaussian())
    }

    /** Exponential sample via inverse CDF: -mean * ln(U). */
    private fun sampleExponential(mean: Double): Double {
        var u = rng.nextDouble()
        while (u == 0.0) u = rng.nextDouble()
        return -mean * ln(u)
    }
}
