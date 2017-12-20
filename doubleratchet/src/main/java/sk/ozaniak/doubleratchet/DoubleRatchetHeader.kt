package sk.ozaniak.doubleratchet

import java.nio.ByteBuffer


/**
 * @author Michal Ozaniak
 */
class DoubleRatchetHeader(val publicKey: ByteArray, val previousChainSize: Int, val messageNumber: Int) {

    fun toByteArray(): ByteArray {
        val publicKeySize = publicKey.size
        val out = ByteArray(publicKeySize + 8)
        System.arraycopy(publicKey, 0, out, 0, publicKeySize)
        val pnInt = ByteBuffer.allocate(4).putInt(previousChainSize).array()
        System.arraycopy(pnInt, 0, out, publicKeySize, 4)
        val nInt = ByteBuffer.allocate(4).putInt(messageNumber).array()
        System.arraycopy(nInt, 0, out, publicKeySize + 4, 4)
        return out
    }

}