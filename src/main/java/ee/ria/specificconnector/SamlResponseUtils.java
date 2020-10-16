package ee.ria.specificconnector;

import io.restassured.response.Response;
import net.shibboleth.utilities.java.support.xml.XMLParserException;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.security.credential.Credential;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class SamlResponseUtils {

    public static Assertion getSamlAssertionFromResponse(Response response, Credential credential) {
        String samlResponse = response.getBody().htmlPath().getString("**.findAll { it.@name == 'SAMLResponse' }[0].@value");
        String decodedSamlResponse = new String(Base64.getDecoder().decode(samlResponse), StandardCharsets.UTF_8);
        SamlSignatureUtils.validateSamlResponseSignature(decodedSamlResponse);
        org.opensaml.saml.saml2.core.Response samlResponseObj = null;
        try {
            samlResponseObj = OpenSAMLUtils.getSamlResponse(decodedSamlResponse);
        } catch (XMLParserException e) {
            e.printStackTrace();
        } catch (UnmarshallingException e) {
            e.printStackTrace();
        }
        return SamlSignatureUtils.decryptAssertion(samlResponseObj.getEncryptedAssertions().get(0), credential);
    }

    public static org.opensaml.saml.saml2.core.Response getSamlResponseFromResponse(Response response) {
        String samlResponse = response.getBody().htmlPath().getString("**.findAll { it.@name == 'SAMLResponse' }[0].@value");
        String decodedSamlResponse = new String(Base64.getDecoder().decode(samlResponse), StandardCharsets.UTF_8);
        SamlSignatureUtils.validateSamlResponseSignature(decodedSamlResponse);
        org.opensaml.saml.saml2.core.Response samlResp = null;
        try {
            samlResp = OpenSAMLUtils.getSamlResponse(decodedSamlResponse);
        } catch (XMLParserException e) {
            e.printStackTrace();
        } catch (UnmarshallingException e) {
            e.printStackTrace();
        }
        return samlResp;
    }
}
