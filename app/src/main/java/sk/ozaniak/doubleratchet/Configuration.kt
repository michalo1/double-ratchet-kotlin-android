package sk.ozaniak.doubleratchet

import java.security.SecureRandom
import java.util.*

/**
 * @author Michal Ozaniak
 */
object Configuration {

    val APP_SPECIFIC_INFO = ByteArray(32)

    init {
        SecureRandom().nextBytes(APP_SPECIFIC_INFO)
    }

}