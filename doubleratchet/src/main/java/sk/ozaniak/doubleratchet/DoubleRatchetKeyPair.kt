package sk.ozaniak.doubleratchet

import org.whispersystems.curve25519.Curve25519KeyPair

/**
 * @author Michal Ozaniak
 */
interface DoubleRatchetKeyPair {
    fun getPublicKey(): ByteArray
    fun getPrivateKey(): ByteArray
    fun getAgreement(publicKey: ByteArray): ByteArray
}