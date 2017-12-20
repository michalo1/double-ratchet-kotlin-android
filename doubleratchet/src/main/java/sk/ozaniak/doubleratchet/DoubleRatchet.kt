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
 * @author Michal Ozaniak
 */
class DoubleRatchet private constructor(val appSpecificInfo: ByteArray,
                                        val maxSkip: Int,
                                        val cryptoEngine: BlockCipher,
                                        val AEADBlockCipher: AEADBlockCipher,
                                        val fixedNonce: ByteArray,
                                        val macSize: Int,
                                        val keyPairGenerator: DoubleRatchetKeyPairGenerator) {

    private constructor(builder: Builder) : this(builder.appSpecificInfo,
            builder.maxSkip,
            builder.cryptoEngine,
            builder.AEADBlockCipher,
            builder.fixedNonce,
            builder.macSize,
            builder.keyPairGenerator)

    companion object {
        inline fun build(appSpecificInfo: ByteArray, block: Builder.() -> Unit) = Builder(appSpecificInfo).apply(block).build()


    }

    class Builder(
            val appSpecificInfo: ByteArray
    ) {
        val maxSkip: Int = 10
        val cryptoEngine: BlockCipher = AESEngine()
        val AEADBlockCipher: AEADBlockCipher = GCMBlockCipher(cryptoEngine)
        val fixedNonce: ByteArray = byteArrayOf(0x24, 0x7b, 0x67, 0x10, 0x19, 0x75, 0x65, 0x41, 0x10, 0x2e)
        val macSize: Int = 128
        val keyPairGenerator: DoubleRatchetKeyPairGenerator = DefaultKeyPairGenerator()

        fun build() = DoubleRatchet(this)
    }

    fun createInitiatorState(sharedKey: ByteArray, publicKey: ByteArray): DoubleRatchetState {
        val keyPair = generateKeyPair()
        val kdfRootKey = kdfRootKey(sharedKey, calculateAgreement(keyPair, publicKey))
        return DoubleRatchetState(keyPair, publicKey, kdfRootKey.first, kdfRootKey.second, null)
    }

    fun createReceiverState(keyPair: DoubleRatchetKeyPair, sharedKey: ByteArray): DoubleRatchetState =
            DoubleRatchetState(keyPair, null, sharedKey, null, null)

    fun ratchetEncrypt(state: DoubleRatchetState, plaintext: String, ad: ByteArray): DoubleRatchetPacket {
        val ckStep = kdfChainKey(state.sendingChainKey!!)
        state.sendingChainKey = ckStep.first
        val mk = ckStep.second
        val header = DoubleRatchetHeader(state.keyPair.getPublicKey(), state.previousChainSize, state.messageNumberSendingChain)
        state.messageNumberSendingChain += 1
        return DoubleRatchetPacket(header, encrypt(mk, plaintext.toByteArray(), ad + header.toByteArray()))
    }

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

    fun generateKeyPair() = keyPairGenerator.generateKeyPair()

    private fun trySkippedMessageKeys(state: DoubleRatchetState, packet: DoubleRatchetPacket, ad: ByteArray): ByteArray? {
        val header = packet.header
        val mk = state.skippedMessageKeys.get(header.publicKey, header.messageNumber)
        if (mk != null) {
            state.skippedMessageKeys.remove(header.publicKey, header.messageNumber)
            return decrypt(mk, packet.body, ad + header.toByteArray())
        } else {
            return null
        }
    }

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

    private fun calculateAgreement(keyPair: DoubleRatchetKeyPair, publicKey: ByteArray)
            = keyPair.getAgreement(publicKey)

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

    private fun encrypt(mk: ByteArray, plainText: ByteArray, associatedData: ByteArray?): ByteArray {
        val params = AEADParameters(KeyParameter(mk), macSize, fixedNonce, associatedData)
        AEADBlockCipher.init(true, params)
        val outBuff = ByteArray(AEADBlockCipher.getOutputSize(plainText.size))
        val offset = AEADBlockCipher.processBytes(plainText, 0, plainText.size, outBuff, 0)
        AEADBlockCipher.doFinal(outBuff, offset)
        return outBuff
    }

    private fun decrypt(mk: ByteArray, cypherText: ByteArray, associatedData: ByteArray?): ByteArray {
        val params = AEADParameters(KeyParameter(mk), macSize, fixedNonce, associatedData)
        AEADBlockCipher.init(false, params)
        val outBuff = ByteArray(AEADBlockCipher.getOutputSize(cypherText.size))
        val offset = AEADBlockCipher.processBytes(cypherText, 0, cypherText.size, outBuff, 0)
        AEADBlockCipher.doFinal(outBuff, offset)
        return outBuff
    }

}