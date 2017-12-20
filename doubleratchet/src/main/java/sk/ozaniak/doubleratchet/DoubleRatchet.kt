package sk.ozaniak.doubleratchet

import org.spongycastle.crypto.BlockCipher
import org.spongycastle.crypto.digests.SHA512Digest
import org.spongycastle.crypto.engines.AESEngine
import org.spongycastle.crypto.generators.HKDFBytesGenerator
import org.spongycastle.crypto.macs.HMac
import org.spongycastle.crypto.modes.AEADBlockCipher
import org.spongycastle.crypto.modes.GCMBlockCipher
import org.spongycastle.crypto.params.AEADParameters
import org.spongycastle.crypto.params.HKDFParameters
import org.spongycastle.crypto.params.KeyParameter
import org.whispersystems.curve25519.Curve25519
import org.whispersystems.curve25519.Curve25519KeyPair

/**
 * Implementation of Double Ratchet algorithm according to implementation guidelines from:
 * https://signal.org/docs/specifications/doubleratchet/#double-ratchet-1
 *
 * @author Michal Ozaniak
 * @version 0.1
 */
class DoubleRatchet private constructor(val appSpecificInfo: ByteArray,
                                        val maxSkip: Int,
                                        val cryptoEngine: BlockCipher,
                                        val AEADBlockCipher: AEADBlockCipher,
                                        val fixedNonce: ByteArray,
                                        val macSize: Int,
                                        val keyPairGenerator: DoubleRatchetKeyPairGenerator) {

    private constructor(builder: Builder) : this(
            builder.appSpecificInfo, // Optional HKDF info parameter. Random app specific byte array
            builder.maxSkip, // Max number of skipped messages in a chain. 10 by default.
            builder.cryptoEngine, // Engine that defines used encryption specification for messages. AES encryption default
            builder.AEADBlockCipher, // Specifies AEAD mode of operation (such as CCM, EAX, GCM,...), GCM mode default
            builder.fixedNonce, // A nonce used for encryption. Can be fixed because each message key is used only once.
            builder.macSize, // Size of MAC used for AEAD in bits. 128 bits default
            builder.keyPairGenerator) // A generator of DH key pair. Uses function Curve25519 by default.

    companion object {
        inline fun build(appSpecificInfo: ByteArray, block: Builder.() -> Unit) = Builder(appSpecificInfo).apply(block).build()
    }

    class Builder(
            val appSpecificInfo: ByteArray
    ) {
        val maxSkip: Int = 10 // 10 Max skipped messages by default
        val cryptoEngine: BlockCipher = AESEngine() // AES encryption by default
        val AEADBlockCipher: AEADBlockCipher = GCMBlockCipher(cryptoEngine) // GCM mode by default
        val fixedNonce: ByteArray = byteArrayOf(0x24, 0x7b, 0x67, 0x10, 0x19, 0x75, 0x65, 0x41, 0x10, 0x2e) // A default nonce
        val macSize: Int = 128 // 128 bits long mac by default
        val keyPairGenerator: DoubleRatchetKeyPairGenerator = DefaultKeyPairGenerator() // Default generator using Curve25519

        fun build() = DoubleRatchet(this)
    }

    fun createInitiatorState(sharedKey: ByteArray, publicKey: ByteArray): DoubleRatchetState {
        val keyPair = generateKeyPair()
        val kdfRootKey = kdfRootKey(sharedKey, calculateAgreement(keyPair, publicKey))
        return DoubleRatchetState(keyPair, publicKey, kdfRootKey.first, kdfRootKey.second, null)
    }

    fun createReceiverState(keyPair: DoubleRatchetKeyPair, sharedKey: ByteArray): DoubleRatchetState =
            DoubleRatchetState(keyPair, null, sharedKey, null, null)

    /**
     * Performs one step in sending chain and encrypts plaintext.
     * @param state current user state
     * @param plaintext plaintext to encrypt
     * @param ad associated data for authenticated encryption
     * @return a packet object containing header and encrypted message
     */
    fun ratchetEncrypt(state: DoubleRatchetState, plaintext: String, ad: ByteArray): DoubleRatchetPacket {
        val ckStep = kdfChainKey(state.sendingChainKey!!)
        state.sendingChainKey = ckStep.first
        val mk = ckStep.second
        val header = DoubleRatchetHeader(state.keyPair.getPublicKey(), state.previousChainSize, state.messageNumberSendingChain)
        state.messageNumberSendingChain += 1
        return DoubleRatchetPacket(header, encrypt(mk, plaintext.toByteArray(), ad + header.toByteArray()))
    }

    /**
     * Checks if the packet corresponds to a skipped message. If yes, message key is used from the
     * saved ones and message decrypted. If it is not a skipped message, a new DH ratchet step is
     * made and new sending and receiving chain are created. Then, a new key is derived inside the
     * receiving chain and the message is decrypted.
     * @param state current user state
     * @param plaintext packet containing header and encrypted data
     * @param ad associated data for authenticated encryption
     * @return a byte array representing decrypted message
     */
    fun ratchetDecrypt(state: DoubleRatchetState, packet: DoubleRatchetPacket, ad: ByteArray): ByteArray {
        val plainText = trySkippedMessageKeys(state, packet, ad)
        if (plainText != null)
            return plainText

        val header = packet.header
        val userDHr = state.receivedPublicKey
        if ((userDHr == null) || !header.publicKey.contentEquals(userDHr)) {
            skipMessageKeys(state, header.previousChainSize)
            DHRatchet(state, packet.header)
        }

        skipMessageKeys(state, header.messageNumber)
        val kdfCk = kdfChainKey(state.receivingChainKey!!)
        state.receivingChainKey = kdfCk.first
        val mk = kdfCk.second
        state.messageNumberReceivingChain += 1
        return decrypt(mk, packet.body, ad + header.toByteArray())
    }

    /**
     * Generate a new DH key pair using Curve25519 by default as recommended in Double Ratchet
     * documentation.
     * @return A public-private key pair using Curve25519
     */
    fun generateKeyPair() = keyPairGenerator.generateKeyPair()

    /**
     * Checks if there is a message key inside the array of skipped message keys for our packet.
     * If yes, returns it.
     * @return skipped message key or null if there is not such message key
     */
    private fun trySkippedMessageKeys(state: DoubleRatchetState, packet: DoubleRatchetPacket, ad: ByteArray): ByteArray? {
        val mk = state.skippedMessageKeys.get(packet.header.publicKey, packet.header.messageNumber)
        if (mk != null) {
            state.skippedMessageKeys.remove(packet.header.publicKey, packet.header.messageNumber)
            return decrypt(mk, packet.body, ad + packet.header.toByteArray())
        } else {
            return null
        }
    }

    /**
     * Checks if number of skipped messages didn't exceed max. If yes, throws an exception. If not,
     * creates skipped message keys in the stack.
     * @param state current state containing reciving chain
     * @param until sending chain size from header of the received message
     */
    private fun skipMessageKeys(state: DoubleRatchetState, until: Int) {
        if (state.messageNumberReceivingChain + maxSkip < until) {
            throw IllegalStateException("MAX_SKIP exceeded")
        }
        val CKr = state.receivingChainKey
        if (CKr != null) {
            while (state.messageNumberReceivingChain < until) {
                val kdf = kdfChainKey(CKr)
                state.receivingChainKey = kdf.first
                state.skippedMessageKeys.put(state.receivedPublicKey!!, state.messageNumberReceivingChain, kdf.second)
                state.messageNumberReceivingChain += 1
            }
        }
    }

    /**
     * Performs a new DH ratchet step.
     * @param state current [DoubleRatchetState] object on which we perform DH ratchet step
     * @param header header of the received message that contains public key for DH
     */
    private fun DHRatchet(state: DoubleRatchetState, header: DoubleRatchetHeader) {
        state.previousChainSize = state.messageNumberSendingChain
        state.messageNumberSendingChain = 0
        state.messageNumberReceivingChain = 0
        state.receivedPublicKey = header.publicKey
        val kdfRk = kdfRootKey(state.rootKey, calculateAgreement(state.keyPair, state.receivedPublicKey!!))
        state.rootKey = kdfRk.first
        state.receivingChainKey = kdfRk.second
        state.keyPair = generateKeyPair()
        val kdfRk2 = kdfRootKey(state.rootKey, calculateAgreement(state.keyPair, state.receivedPublicKey!!))
        state.rootKey = kdfRk2.first
        state.sendingChainKey = kdfRk2.second
    }

    /**
     * Returns shared secret key for our key pair and received public key
     */
    private fun calculateAgreement(keyPair: DoubleRatchetKeyPair, publicKey: ByteArray)
            = keyPair.getAgreement(publicKey)

    /**
     * KDF function used for the root chain based on HKDF and SHA512 as recommended in documentation
     * of Double Ratchet
     * @param rk current root key
     * @param dhOut output of DH ratchet step
     * @return pair of 32 byte long new root key and 32 byte long new chain key
     */
    private fun kdfRootKey(rk: ByteArray, dhOut: ByteArray): Pair<ByteArray, ByteArray> {
        val hkdfParameters = HKDFParameters(dhOut, rk, appSpecificInfo)
        val out = ByteArray(64)
        val hkdfGenerator = HKDFBytesGenerator(SHA512Digest())
        hkdfGenerator.init(hkdfParameters)
        hkdfGenerator.generateBytes(out, 0, 64)
        val newRk = out.take(32)
        val newCk = out.takeLast(32)
        return Pair(newRk.toByteArray(), newCk.toByteArray())
    }

    /**
     * KDF function used for the sending and the receiving chains based on HMAC and SHA512
     * as recommended in documentation of Double Ratchet
     * @param ck current chain key
     * @return pair of 32 byte long new chain key and 32 byte long new message key
     */
    private fun kdfChainKey(ck: ByteArray): Pair<ByteArray, ByteArray> {
        val param = KeyParameter(ck)
        val hmacGenerator = HMac(SHA512Digest())
        hmacGenerator.init(param)
        val buff = ByteArray(64)
        hmacGenerator.doFinal(buff, 0)
        val newCk = buff.take(32)
        val newMk = buff.takeLast(32)
        return Pair(newCk.toByteArray(), newMk.toByteArray())
    }

    /**
     * Encrypts data using AES encryption in GCM mode of operation. AEAD accepts message key,
     * plaintext and some associated data used for authentication.
     * @return encrypted data
     */
    private fun encrypt(mk: ByteArray, plainText: ByteArray, associatedData: ByteArray?): ByteArray {
        val params = AEADParameters(KeyParameter(mk), macSize, fixedNonce, associatedData)
        AEADBlockCipher.init(true, params)
        val outBuff = ByteArray(AEADBlockCipher.getOutputSize(plainText.size))
        val offset = AEADBlockCipher.processBytes(plainText, 0, plainText.size, outBuff, 0)
        AEADBlockCipher.doFinal(outBuff, offset)
        return outBuff
    }

    /**
     * Decrypts data using the same algorithms as for encryption. See [encrypt].
     * @return decrypted data
     */
    private fun decrypt(mk: ByteArray, cypherText: ByteArray, associatedData: ByteArray?): ByteArray {
        val params = AEADParameters(KeyParameter(mk), macSize, fixedNonce, associatedData)
        AEADBlockCipher.init(false, params)
        val outBuff = ByteArray(AEADBlockCipher.getOutputSize(cypherText.size))
        val offset = AEADBlockCipher.processBytes(cypherText, 0, cypherText.size, outBuff, 0)
        AEADBlockCipher.doFinal(outBuff, offset)
        return outBuff
    }

}