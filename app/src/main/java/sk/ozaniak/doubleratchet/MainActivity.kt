package sk.ozaniak.doubleratchet

import android.support.v7.app.AppCompatActivity
import android.os.Bundle
import org.whispersystems.curve25519.Curve25519

class MainActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val doubleRatchet = DoubleRatchetManager.doubleRatchet

        // Established shared key
        val keyPairAlice = doubleRatchet.generateKeyPair()
        val keyPairBob = doubleRatchet.generateKeyPair()
        val SKBob = keyPairBob.getAgreement(keyPairAlice.getPublicKey())
        val SKAlice = keyPairAlice.getAgreement(keyPairBob.getPublicKey())

        // Initializing Bob
        val bob = User("Bob", doubleRatchet.createReceiverState(keyPairBob, SKBob))

        // Initializing Alice
        val alice = User("Alice", doubleRatchet.createInitiatorState(SKAlice, keyPairBob.getPublicKey()))

        // Test 1
        alice.sendMessage(bob, "Hello Bob!")
        bob.sendMessage(alice, "Hi Alice, how are you?")
        alice.sendMessage(bob, "I'm fine, what about you?")
        bob.sendMessage(alice, "Perfect")

        // Test 2
        bob.sendMessage(alice, "Bob's second message in a row")
        bob.sendMessage(alice, "Bob's third message in a row")

        // Test 3
        alice.sendMessage(bob, "Alice's first message in a row")
        alice.sendMessage(bob, "Alice's second message in a row")
        alice.sendMessage(bob, "Alice's third message in a row")

        // Test 4
        val undeliveredPacket1 = bob.forceSkipMessage(alice, "Bob's skipped message")
        bob.sendMessage(alice, "Bob's message after skipped message")
        bob.deliverSkippedMessage(alice, undeliveredPacket1)
    }

}
