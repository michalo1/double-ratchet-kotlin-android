package sk.ozaniak.doubleratchet

import android.util.Log


/**
 * @author Michal Ozaniak
 */
class User(val name: String, val state: DoubleRatchetState) {

    fun sendMessage(recipient: User, message: String) {
        Log.d("User", name + " sent message to " + recipient.name + ": " + message)
        val packet = DoubleRatchetManager.doubleRatchet.ratchetEncrypt(state, message, recipient.name.toByteArray())
        sendPacket(recipient, packet)
    }

    fun forceSkipMessage(recipient: User, message: String): DoubleRatchetPacket {
        Log.d("User", name + "'s message to " + recipient.name + " that is not delivered: " + message)
        return DoubleRatchetManager.doubleRatchet.ratchetEncrypt(state, message, recipient.name.toByteArray())
    }

    fun deliverSkippedMessage(recipient: User, packet: DoubleRatchetPacket) {
        sendPacket(recipient, packet)
    }

    private fun onMessageReceived(sender: User, message: String) {
        Log.d("User", name + " received message from " + sender.name + ": " + message)
    }

    private fun sendPacket(recipient: User, packet: DoubleRatchetPacket) {
        recipient.onPacketReceived(this, packet)
    }

    private fun onPacketReceived(sender: User, packet: DoubleRatchetPacket) {
        val message = DoubleRatchetManager.doubleRatchet.ratchetDecrypt(state, packet, this.name.toByteArray())
        onMessageReceived(sender, String(message))
    }

}