package sk.ozaniak.doubleratchet

/**
 * @author Michal Ozaniak
 */
data class DoubleRatchetPacket(
        val header: DoubleRatchetHeader,
        val body: ByteArray
)