package ee.ria.specificconnector

import org.opensaml.saml.saml2.core.Assertion

class SamlUtils {

    static String getLoaValue(Assertion assertion) {
        return assertion.getAuthnStatements().get(0).getAuthnContext().getAuthnContextClassRef().getAuthnContextClassRef()
    }

}
