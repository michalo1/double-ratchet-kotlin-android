package sk.ozaniak.doubleratchet

import org.whispersystems.curve25519.Curve25519
import org.whispersystems.curve25519.Curve25519KeyPair

/**
 * @author Michal Ozaniak
 */
class DefaultKeyPair(val curve25519KeyPair: Curve25519KeyPair) : DoubleRatchetKeyPair {

    override fun getPublicKey(): ByteArray = curve25519KeyPair.publicKey

    override fun getPrivateKey(): ByteArray = curve25519KeyPair.privateKey

    override fun getAgreement(publicKey: ByteArray): ByteArray =
            Curve25519.getInstance(Curve25519.BEST).calculateAgreement(publicKey, curve25519KeyPair.privateKey)

}