package ee.ria.specificconnector

import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response
import org.opensaml.saml.saml2.core.Assertion
import org.opensaml.saml.saml2.core.AuthnContextComparisonTypeEnumeration
import org.opensaml.saml.saml2.core.NameIDType
import spock.lang.Unroll

import static org.junit.Assert.assertEquals


class AuthenticationSpec extends SpecificConnectorSpecification {
    public static final String FN_DATE = "DateOfBirth"
    public static final String FN_PNO = "PersonIdentifier"
    public static final String FN_FAMILY = "FamilyName"
    public static final String FN_FIRST = "FirstName"

    Flow flow = new Flow(props)

    def setup() {
        flow.connector.signatureCredential = signatureCredential
        flow.connector.encryptionCredential = encryptionCredential
        flow.cookieFilter = new CookieFilter()
    }

    @Unroll
    @Feature("eIDAS-Node implementations MUST support the following SAML 2.0 name identifier formats")
    def "request authentication with name identifier format: #nameIdFormat"() {
        expect:
        String samlRequest = Steps.getAuthnRequest(flow, "DEMO-SP-CA", "http://eidas.europa.eu/LoA/high", AuthnContextComparisonTypeEnumeration.MINIMUM, nameIdFormat)
        Response taraLoginPageResponse = Steps.startAuthProcessFollowRedirectsToTara(flow, samlRequest)
        Response consentPageResponse = Steps.authenticateWithMidAndFollowRedirects(flow, taraLoginPageResponse)
        Response authenticationResponse = Steps.userConsentAndFollowRedirects(flow, consentPageResponse)

        Assertion assertion = SamlResponseUtils.getSamlAssertionFromResponse(authenticationResponse, flow.connector.encryptionCredential)

        assertEquals("Correct LOA is returned", "http://eidas.europa.eu/LoA/high", SamlUtils.getLoaValue(assertion))
        assertEquals("Correct family name is returned", familyName, SamlUtils.getAttributeValue(assertion, FN_FAMILY))
        assertEquals("Correct first name is returned", firstName, SamlUtils.getAttributeValue(assertion, FN_FIRST))
        assertEquals("Correct id code is returned", personalNumber, SamlUtils.getAttributeValue(assertion, FN_PNO))
        assertEquals("Correct birth date is returned", dateOfBirth, SamlUtils.getAttributeValue(assertion, FN_DATE))
        assertEquals("Correct nameIdFormat is returned", nameIdFormat, SamlUtils.getSubjectNameIdFormatValue(assertion))

        where:
        nameIdFormat           || familyName                   || firstName     || personalNumber      || dateOfBirth  || loa_level
        NameIDType.TRANSIENT   || "O’CONNEŽ-ŠUSLIK TESTNUMBER" || "MARY ÄNN"    || "EE/CA/60001019906" || "2000-01-01" || "http://eidas.europa.eu/LoA/high"
        NameIDType.PERSISTENT  || "O’CONNEŽ-ŠUSLIK TESTNUMBER" || "MARY ÄNN"    || "EE/CA/60001019906" || "2000-01-01" || "http://eidas.europa.eu/LoA/high"
        NameIDType.UNSPECIFIED || "O’CONNEŽ-ŠUSLIK TESTNUMBER" || "MARY ÄNN"    || "EE/CA/60001019906" || "2000-01-01" || "http://eidas.europa.eu/LoA/high"
    }

    @Unroll
    @Feature("eIDAS-Node implementations MUST support requests without name identifier formats attribute")
    def "request authentication without name identifier format"() {
        expect:
        String samlRequest = Steps.getAuthnRequestWithoutNameIdFormat(flow, "DEMO-SP-CA", "http://eidas.europa.eu/LoA/high", AuthnContextComparisonTypeEnumeration.MINIMUM)
        Response taraLoginPageResponse = Steps.startAuthProcessFollowRedirectsToTara(flow, samlRequest)
        Response consentPageResponse = Steps.authenticateWithMidAndFollowRedirects(flow, taraLoginPageResponse)
        Response authenticationResponse = Steps.userConsentAndFollowRedirects(flow, consentPageResponse)

        Assertion assertion = SamlResponseUtils.getSamlAssertionFromResponse(authenticationResponse, flow.connector.encryptionCredential)

        assertEquals("Correct LOA is returned", "http://eidas.europa.eu/LoA/high", SamlUtils.getLoaValue(assertion))
        assertEquals("Correct family name is returned", familyName, SamlUtils.getAttributeValue(assertion, FN_FAMILY))
        assertEquals("Correct first name is returned", firstName, SamlUtils.getAttributeValue(assertion, FN_FIRST))
        assertEquals("Correct id code is returned", personalNumber, SamlUtils.getAttributeValue(assertion, FN_PNO))
        assertEquals("Correct birth date is returned", dateOfBirth, SamlUtils.getAttributeValue(assertion, FN_DATE))
        assertEquals("Correct nameIdFormat is returned", nameIdFormat, SamlUtils.getSubjectNameIdFormatValue(assertion))

        where:
        nameIdFormat           || familyName                   || firstName     || personalNumber      || dateOfBirth  || loa_level
        NameIDType.UNSPECIFIED || "O’CONNEŽ-ŠUSLIK TESTNUMBER" || "MARY ÄNN"    || "EE/CA/60001019906" || "2000-01-01" || "http://eidas.europa.eu/LoA/high"
    }

    @Unroll
    @Feature("To support reuse of eIDAS-Node infrastructure for non-notified eID schemes, Member States MAY support other URIs as Authentication Context")
    def "request authentication with supported comparison: #comparisonLevel and requested LOA: #requestLoa"() {
        expect:
        String samlRequest = Steps.getAuthnRequest(flow, "DEMO-SP-CA", requestLoa, comparisonLevel)
        Response taraLoginPageResponse = Steps.startAuthProcessFollowRedirectsToTara(flow, samlRequest)
        Response consentPageResponse = Steps.authenticateWithMidAndFollowRedirects(flow, taraLoginPageResponse)
        Response authenticationResponse = Steps.userConsentAndFollowRedirects(flow, consentPageResponse)

        Assertion assertion = SamlResponseUtils.getSamlAssertionFromResponse(authenticationResponse, flow.connector.encryptionCredential)

        assertEquals("Correct LOA is returned", responseLoa, SamlUtils.getLoaValue(assertion))

        where:
        comparisonLevel                               | requestLoa                                   || responseLoa
        AuthnContextComparisonTypeEnumeration.MINIMUM | "http://eidas.europa.eu/LoA/high"            || "http://eidas.europa.eu/LoA/high"
    }

    @Unroll
    @Feature("To support reuse of eIDAS-Node infrastructure for non-notified eID schemes, Member States MAY support other URIs as Authentication Context")
    def "request authentication with not supported comparison: #comparisonLevel and requested LOA: #requestLoa"() {
        expect:
        String samlRequest = Steps.getAuthnRequest(flow, "DEMO-SP-CA", requestLoa, comparisonLevel)
        Response response = Requests.getAuthenticationPage(flow, samlRequest)

        assertEquals("Error is returned", errorResponse, response.body().htmlPath().get("**.find {it.@class == 'text-center'}"))

        where:
        comparisonLevel                               | requestLoa                                   || errorResponse
        AuthnContextComparisonTypeEnumeration.EXACT   | "http://eidas.europa.eu/LoA/high"            || "003007 - value of Level of Assurance is not supported"
        AuthnContextComparisonTypeEnumeration.EXACT   | "http://eidas.europa.eu/NotNotified/LoA/low" || "003007 - value of Level of Assurance is not supported"
    }
}
