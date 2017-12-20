package sk.ozaniak.doubleratchet

import com.google.common.collect.HashBasedTable
import org.whispersystems.curve25519.Curve25519KeyPair

/**
 * @author Michal Ozaniak
 */
data class DoubleRatchetState(
        var keyPair: DoubleRatchetKeyPair,
        var receivedPublicKey: ByteArray?,
        var rootKey: ByteArray,
        var sendingChainKey: ByteArray?,
        var receivingChainKey: ByteArray?
) {

    var messageNumberSendingChain: Int = 0
    var messageNumberReceivingChain: Int = 0
    var previousChainSize: Int = 0
    val skippedMessageKeys: HashBasedTable<ByteArray, Int, ByteArray> = HashBasedTable.create<ByteArray, Int, ByteArray>()

}