package ee.ria.specificconnector

import org.opensaml.core.xml.schema.XSAny
import org.opensaml.saml.saml2.core.Assertion
import org.opensaml.saml.saml2.core.Attribute

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
}
