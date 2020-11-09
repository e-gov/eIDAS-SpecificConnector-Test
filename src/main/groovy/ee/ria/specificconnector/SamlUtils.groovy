package ee.ria.specificconnector

import org.opensaml.saml.saml2.core.Assertion
import org.spockframework.lang.Wildcard

import java.time.LocalDateTime
import java.time.format.DateTimeFormatter

class SamlUtils {

    static String getLoaValue(Assertion assertion) {
        return assertion.getAuthnStatements().get(0).getAuthnContext().getAuthnContextClassRef().getAuthnContextClassRef()
    }

    static Map setUrlParameter(Map hashMap, Object param, Object paramValue) {
        if (!(param instanceof Wildcard)) {
            if (!(paramValue instanceof Wildcard)) {
                hashMap.put(param, paramValue)
            } else {
                hashMap.put(param, "")
            }
        }
        return hashMap
    }

    static boolean isValidUUID(String uuid) {
        def matcher = uuid =~ /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/
        return matcher.matches()
    }

    static boolean isValidDateTime(String datetime) {
        String pattern = "yyyy-MM-dd HH:mm:ss SSS";
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern(pattern);
        LocalDateTime timestamp = LocalDateTime.parse(datetime, formatter)
        if (datetime.equals(timestamp.format(pattern)))
            return true
        else
            return false
    }
}
