package sk.ozaniak.doubleratchet

/**
 * @author Michal Ozaniak
 */
interface DoubleRatchetKeyPairGenerator {
    fun generateKeyPair(): DoubleRatchetKeyPair
}