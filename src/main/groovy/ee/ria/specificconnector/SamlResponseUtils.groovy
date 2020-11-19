package ee.ria.specificconnector

import net.shibboleth.utilities.java.support.xml.XMLParserException
import org.opensaml.core.xml.io.UnmarshallingException
import io.restassured.response.Response
import org.opensaml.saml.saml2.core.Assertion
import org.opensaml.security.credential.Credential

import java.nio.charset.StandardCharsets

class SamlResponseUtils {
    static Assertion extractSamlAssertion(Response samlResponse, Credential encryptionCredential) {
        return decryptSamlAssertion(decodeSamlResponse(samlResponse), encryptionCredential);
    }

    static Assertion extractSamlAssertionFromPost(Response samlResponse, Credential encryptionCredential) {
        return decryptSamlAssertion(decodeSamlResponseFromPost(samlResponse), encryptionCredential);
    }

    static String decodeSamlResponseFromPost(Response response) {
        String SAMLresponseToAssert = response.getBody().htmlPath().getString("**.find { it.@name == 'SAMLResponse' }.@value")
        return new String(Base64.getDecoder().decode(SAMLresponseToAssert), StandardCharsets.UTF_8);
    }

    static String decodeSamlResponse(Response response) {
        String urlEncodedSAMLresponse = response.getHeader("location").toURL().getQuery().split("&")[0].split("=")[1];
        String SAMLresponseToAssert = URLDecoder.decode(urlEncodedSAMLresponse, "UTF-8");
        return new String(Base64.getDecoder().decode(SAMLresponseToAssert), StandardCharsets.UTF_8);
    }

    static Assertion decryptSamlAssertion(String xmlSamlResponse, Credential encryptionCredential) {
        org.opensaml.saml.saml2.core.Response samlResponseObj = null;
        try {
            samlResponseObj = OpenSAMLUtils.getSamlResponse(xmlSamlResponse);
        } catch (XMLParserException e) {
            e.printStackTrace();
        } catch (UnmarshallingException e) {
            e.printStackTrace();
        }
        return SamlSignatureUtils.decryptAssertion(samlResponseObj.getEncryptedAssertions().get(0), encryptionCredential);
    }
}
