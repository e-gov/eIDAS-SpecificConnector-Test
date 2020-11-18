package ee.ria.specificconnector

import org.apache.xml.security.exceptions.Base64DecodingException
import org.opensaml.core.xml.schema.XSAny
import org.opensaml.saml.saml2.core.Assertion
import org.opensaml.saml.saml2.core.Attribute
import org.spockframework.lang.Wildcard

import java.nio.charset.StandardCharsets
import java.time.LocalDateTime
import java.time.format.DateTimeFormatter

class SamlUtils {

    static String getAttributeValue(Assertion assertion, String friendlyName) {
        for (Attribute attribute : assertion.getAttributeStatements().get(0).getAttributes()) {
            if (attribute.getFriendlyName().equals(friendlyName)) {
                XSAny attributeValue = (XSAny) attribute.getAttributeValues().get(0)
                return attributeValue.getTextContent()
            }
        }
        throw new RuntimeException("No such attribute found: " + friendlyName)
    }

    static String getLoaValue(Assertion assertion) {
        return assertion.getAuthnStatements().get(0).getAuthnContext().getAuthnContextClassRef().getAuthnContextClassRef()
    }

    static String getSubjectNameIdFormatValue(Assertion assertion) {
        return assertion.getSubject().getNameID().getFormat()
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

    static boolean isValidXMLDateTime(String datetime) {
        String pattern = "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'";
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern(pattern);
        LocalDateTime timestamp = LocalDateTime.parse(datetime, formatter)
        if (datetime.equals(timestamp.format(pattern)))
            return true
        else
            return false
    }

    static boolean isBase64EncodedString(String encodedString) {
        if (encodedString.isBlank()) {
            return false
        } else {
            try {
                String string = new String(Base64.getDecoder().decode(encodedString), StandardCharsets.UTF_8);
            } catch (Base64DecodingException e) {
                return false
            }
            return true
        }
    }

    static String decodeBase64(String encodedString) {
        return new String(Base64.getDecoder().decode(encodedString), StandardCharsets.UTF_8);
    }
}
