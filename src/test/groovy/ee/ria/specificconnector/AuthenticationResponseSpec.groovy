package ee.ria.specificconnector

import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.path.xml.XmlPath
import io.restassured.path.xml.config.XmlPathConfig
import io.restassured.response.Response
import org.hamcrest.Matchers
import io.restassured.matcher.RestAssuredMatchers
import spock.lang.Unroll
import org.opensaml.saml.saml2.core.Assertion
import org.apache.commons.validator.routines.InetAddressValidator

import java.security.cert.X509Certificate;
import org.opensaml.security.x509.X509Support;
import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter

import static org.junit.Assert.assertEquals
import static org.junit.Assert.assertThat
import static org.junit.Assert.assertTrue

class AuthenticationResponseSpec extends EEConnectorSpecification {

    static String REQUEST_TYPE_POST = "post"
    static String REQUEST_TYPE_GET = "get"

    Flow flow = new Flow(props)

    def setup() {
        flow.domesticSpService.signatureCredential = signatureCredential
        flow.domesticSpService.encryptionCredential = encryptionCredential
        flow.domesticConnector.connectorSigningCertificate = connectorSigningCertificate
        flow.domesticSpService.encryptionCertificate = encryptionCertificate
        flow.cookieFilter = new CookieFilter()
    }

    @Unroll
    @Feature("AUTHENTICATION_RESPONSE_SUCCESS")
    def "get authentication response get"() {
        expect:
        String samlRequest = Steps.getAuthnRequest(flow, "eidas-eeserviceprovider")
        Steps.startAuthenticationFlow(flow, REQUEST_TYPE_GET, samlRequest)
        Steps.continueAuthenticationFlow(flow, REQUEST_TYPE_GET)
        Response authenticationResponse = Requests.getAuthorizationResponseFromEidas(flow, REQUEST_TYPE_GET, flow.nextEndpoint, flow.token)
        assertEquals("Correct HTTP status code is returned", 302, authenticationResponse.statusCode())
        Assertion samlAssertion = SamlResponseUtils.extractSamlAssertion(authenticationResponse, flow.domesticSpService.encryptionCredential)
        assertEquals("Correct LOA is returned", "http://eidas.europa.eu/LoA/high", SamlUtils.getLoaValue(samlAssertion))
    }

    @Unroll
    @Feature("AUTHENTICATION_RESPONSE_SUCCESS")
    def "get authentication response post"() {
        expect:
        String samlRequest = Steps.getAuthnRequest(flow, "eidas-eeserviceprovider")
        Steps.startAuthenticationFlow(flow, REQUEST_TYPE_POST, samlRequest)
        Steps.continueAuthenticationFlow(flow, REQUEST_TYPE_POST)
        Response authenticationResponse = Requests.getAuthorizationResponseFromEidas(flow, REQUEST_TYPE_POST, flow.nextEndpoint, flow.token)
        assertEquals("Correct HTTP status code is returned", 200, authenticationResponse.statusCode())
        Assertion samlAssertion = SamlResponseUtils.extractSamlAssertionFromPost(authenticationResponse, flow.domesticSpService.encryptionCredential)
        assertEquals("Correct LOA is returned", "http://eidas.europa.eu/LoA/high", SamlUtils.getLoaValue(samlAssertion))
    }

    @Unroll
    @Feature("AUTHENTICATION_RESPONSE_SUCCESS")
    def "validate authentication response post"() {
        expect:
        String samlRequest = Steps.getAuthnRequest(flow, "eidas-eeserviceprovider")
        Steps.startAuthenticationFlow(flow, REQUEST_TYPE_POST, samlRequest)
        Steps.continueAuthenticationFlow(flow, REQUEST_TYPE_POST)
        Response authenticationResponse = Requests.getAuthorizationResponseFromEidas(flow, REQUEST_TYPE_POST, flow.nextEndpoint, flow.token)
        assertEquals("Correct HTTP status code is returned", 200, authenticationResponse.statusCode())
        Assertion samlAssertion = SamlResponseUtils.extractSamlAssertionFromPost(authenticationResponse, flow.domesticSpService.encryptionCredential)
        assertEquals("Correct LOA is returned", "http://eidas.europa.eu/LoA/high", SamlUtils.getLoaValue(samlAssertion))
        String samlResponseXML = SamlResponseUtils.decodeSamlResponseFromPost(authenticationResponse)
        // assertThat(samlResponseXML, RestAssuredMatchers.matchesXsd(new File("src/test/resources/saml-schema-protocol-2.0.xsd")))
        XmlPath xmlPath = new XmlPath(samlResponseXML).using(new XmlPathConfig("UTF-8"));
        String destination = xmlPath.getString("Response.@Destination")
        assertEquals("Destination attribute is URI", destination, new URL(destination).toURI().toString())
        assertEquals("ID attribute length", 64, xmlPath.getString("Response.@ID").length())
        assertEquals("InResponseTo attribute length", 33, xmlPath.getString("Response.@InResponseTo").length())
        assertTrue(SamlUtils.isValidXMLDateTime(xmlPath.get("Response.@IssueInstant")))
        assertEquals("Correct Version attribute value", "2.0", xmlPath.getString("Response.@Version"))
        assertEquals("Correct Issuer", flow.domesticConnector.fullMetadataUrl.toString(), xmlPath.getString("Response.Issuer"))
        assertEquals("Correct Issuer Format", "urn:oasis:names:tc:SAML:2.0:nameid-format:entity", xmlPath.getString("Response.Issuer.@Format"))
        assertTrue(SamlUtils.isBase64EncodedString(xmlPath.getString("Response.Signature.SignedInfo.Reference.DigestValue")))
        assertEquals("Correct StatusCode", "urn:oasis:names:tc:SAML:2.0:status:Success", xmlPath.getString("Response.Status.StatusCode.@Value"))
        assertTrue(xmlPath.getString("Response.EncryptedAssertion").length() > 11000)
    }

    @Unroll
    @Feature("AUTHENTICATION_RESPONSE_SUCCESS")
    def "validate authentication response get"() {
        expect:
        String samlRequest = Steps.getAuthnRequest(flow, "eidas-eeserviceprovider")
        Steps.startAuthenticationFlow(flow, REQUEST_TYPE_GET, samlRequest)
        Steps.continueAuthenticationFlow(flow, REQUEST_TYPE_GET)
        Response authenticationResponse = Requests.getAuthorizationResponseFromEidas(flow, REQUEST_TYPE_GET, flow.nextEndpoint, flow.token)
        assertEquals("Correct HTTP status code is returned", 302, authenticationResponse.statusCode())
        Assertion samlAssertion = SamlResponseUtils.extractSamlAssertion(authenticationResponse, flow.domesticSpService.encryptionCredential)
        assertEquals("Correct LOA is returned", "http://eidas.europa.eu/LoA/high", SamlUtils.getLoaValue(samlAssertion))
        String samlResponseXML = SamlResponseUtils.decodeSamlResponse(authenticationResponse)
        // assertThat(samlResponseXML, RestAssuredMatchers.matchesXsd(new File("src/test/resources/saml-schema-protocol-2.0.xsd")))
        XmlPath xmlPath = new XmlPath(samlResponseXML).using(new XmlPathConfig("UTF-8"));
        String destination = xmlPath.getString("Response.@Destination")
        assertEquals("Destination attribute is URI", destination, new URL(destination).toURI().toString())
        assertEquals("ID attribute length", 64, xmlPath.getString("Response.@ID").length())
        assertEquals("InResponseTo attribute length", 33, xmlPath.getString("Response.@InResponseTo").length())
        assertTrue(SamlUtils.isValidXMLDateTime(xmlPath.get("Response.@IssueInstant")))
        assertEquals("Correct Version attribute value", "2.0", xmlPath.getString("Response.@Version"))
        assertEquals("Correct Issuer", flow.domesticConnector.fullMetadataUrl.toString(), xmlPath.getString("Response.Issuer"))
        assertEquals("Correct Issuer Format", "urn:oasis:names:tc:SAML:2.0:nameid-format:entity", xmlPath.getString("Response.Issuer.@Format"))
        assertTrue(SamlUtils.isBase64EncodedString(xmlPath.getString("Response.Signature.SignedInfo.Reference.DigestValue")))
        assertEquals("Correct StatusCode", "urn:oasis:names:tc:SAML:2.0:status:Success", xmlPath.getString("Response.Status.StatusCode.@Value"))
        assertTrue(xmlPath.getString("Response.EncryptedAssertion").length() > 11000)
        String[] samlResponse = authenticationResponse.getHeader("location").toURL().getQuery().split("&")[0].split("=")
        assertEquals("Correct URL attribute name SAMLResponse", "SAMLResponse", samlResponse[0])
        String[] relayState = authenticationResponse.getHeader("location").toURL().getQuery().split("&")[1].split("=")
        assertEquals("Correct URL attribute name RelayState", "RelayState", relayState[0])
        assertTrue("Correct URL attribute RelayState value length", relayState[1].length() > 35)
    }

    @Unroll
    @Feature("AUTHENTICATION_RESPONSE_SUCCESS")
    def "validate authentication response assertion post"() {
        expect:
        String samlRequest = Steps.getAuthnRequest(flow, "eidas-eeserviceprovider")

        Steps.startAuthenticationFlow(flow, REQUEST_TYPE_POST, samlRequest)
        Steps.continueAuthenticationFlow(flow, REQUEST_TYPE_POST)
        Response authenticationResponse = Requests.getAuthorizationResponseFromEidas(flow, REQUEST_TYPE_POST, flow.nextEndpoint, flow.token)
        assertEquals("Correct HTTP status code is returned", 200, authenticationResponse.statusCode())
        Assertion samlAssertion = SamlResponseUtils.extractSamlAssertionFromPost(authenticationResponse, flow.domesticSpService.encryptionCredential)
        assertEquals("Correct LOA is returned", "http://eidas.europa.eu/LoA/high", SamlUtils.getLoaValue(samlAssertion))
        // TODO Uncomment if bug is fixed
        //assertEquals("Correct ID is returned", flow.domesticSpService.samlRequestId, samlAssertion.getID())

        String samlResponseXML = SamlResponseUtils.decodeSamlResponseFromPost(authenticationResponse)
        XmlPath xmlPath = new XmlPath(samlResponseXML).using(new XmlPathConfig("UTF-8"));
        String responseIssueInstant = xmlPath.getString("Response.@IssueInstant")
        assertEquals("Correct IssueInstant is returned", responseIssueInstant, samlAssertion.getIssueInstant().toString())
        assertEquals("Correct Assertion Version attribute value", "2.0", samlAssertion.getVersion().toString())
        assertEquals("Correct Assertion Issuer Format", "urn:oasis:names:tc:SAML:2.0:nameid-format:entity", samlAssertion.getIssuer().getFormat())
        assertEquals("Correct Assertion Issuer", flow.domesticConnector.fullMetadataUrl.toString(), samlAssertion.getIssuer().getValue())

       // assertEquals("Correct nameID", "0123456", samlAssertion.getSubject().getNameID().getValue())
        assertEquals("Correct subject confirmation method", "urn:oasis:names:tc:SAML:2.0:cm:bearer", samlAssertion.getSubject().getSubjectConfirmations().get(0).getMethod())
        String samlAssertionIPAddress = samlAssertion.getSubject().getSubjectConfirmations().get(0).getSubjectConfirmationData().getAddress()
        assertTrue("Correct IP address in assertion returned", InetAddressValidator.getInstance().isValidInet4Address(samlAssertionIPAddress))
        String samlAssertionInResponseTo = samlAssertion.getSubject().getSubjectConfirmations().get(0).getSubjectConfirmationData().getInResponseTo()
        assertEquals("Correct InResponseTo in assertion returned", flow.domesticSpService.samlRequestId, samlAssertionInResponseTo)
        def duration = ZonedDateTime.parse(samlAssertion.getIssueInstant().toString(), DateTimeFormatter.ISO_DATE_TIME) >> ZonedDateTime.parse(samlAssertion.getSubject().getSubjectConfirmations().get(0).getSubjectConfirmationData().getNotOnOrAfter().toString(), DateTimeFormatter.ISO_DATE_TIME)

        assertTrue("Correct NotOnOrAfter in assertion returned", Math.abs(duration.seconds) < 330 )
        assertEquals("Correct Assertion return URL", flow.domesticSpService.fullReturnUrl.toString(), samlAssertion.getSubject().getSubjectConfirmations().get(0).getSubjectConfirmationData().getRecipient())
        assertEquals("Correct conditions notBefore", responseIssueInstant, samlAssertion.getConditions().getNotBefore().toString())
        assertEquals("Correct conditions NotOnOrAfter", samlAssertion.getIssueInstant().plusMinutes(5).toString(), samlAssertion.getConditions().notOnOrAfter.toString())
        assertEquals("Correct conditions Audience", flow.domesticSpService.fullMetadataUrl.toString(), samlAssertion.getConditions().getAudienceRestrictions().get(0).getAudiences().get(0).getAudienceURI())
        assertEquals("Correct authnstatement AuthnInstant", responseIssueInstant, samlAssertion.getAuthnStatements().get(0).getAuthnInstant().toString())
        assertEquals("Correct DateOfBirth is returned", "1965-01-01", SamlUtils.getAttributeValue(samlAssertion, "DateOfBirth"))
        assertEquals("Correct PersonIdentifier is returned", "CA/EE/12345", SamlUtils.getAttributeValue(samlAssertion, "PersonIdentifier"))
        assertEquals("Correct FamilyName is returned", "Garcia", SamlUtils.getAttributeValue(samlAssertion, "FamilyName"))
        assertEquals("Correct FirstName is returned", "javier", SamlUtils.getAttributeValue(samlAssertion, "FirstName"))
    }

    @Unroll
    @Feature("AUTHENTICATION_RESULT_LIGHTTOKEN_ACCEPTANCE")
    def "request authentication with invalid lightToken"() {
        expect:
        String invalidToken = "specificCommunicationDefinitionConnectorResponse|b45e99b0-afef-44dc-b299-6ede26e5b61b|2020-11-02 10:12:15 522|WarR5kd669/NZiysHeRtog90PAZ3dAXeusmss8/Bl3s="
        String encodedToken = new String(Base64.getEncoder().encode(invalidToken.getBytes()))
        Response response = Requests.getAuthorizationResponseFromEidas(flow, REQUEST_TYPE_POST, flow.domesticConnector.fullEidasResponseUrl, encodedToken)
        assertEquals("Correct HTTP status code is returned", 400, response.statusCode())
        assertEquals("Correct content type", "application/json", response.getContentType())
        assertThat(response.body().jsonPath().get("incidentNumber"), Matchers.notNullValue())
        assertThat(response.body().jsonPath().get("message").toString(), Matchers.equalTo("Token is invalid"))
    }

    @Unroll
    @Feature("AUTHENTICATION_RESULT_ENDPOINT")
    @Feature("AUTHENTICATION_RESULT_LIGHTTOKEN_ACCEPTANCE")
    def "request authentication response with other parameters"() {
        expect:
        String expiredEncodedToken = "c3BlY2lmaWNDb21tdW5pY2F0aW9uRGVmaW5pdGlvbkNvbm5lY3RvclJlc3BvbnNlfGM4NGE4NGUyLWRhNmQtNGFkMi1hNGIwLWEwNWMzMDA2MTJiYnwyMDIwLTExLTA1IDAwOjIwOjM3IDcwOXxKdGtoVFlJYXZjMy9sU3ZjZm8yM2xSOGxabUpzQ2xELzlwQVZQYzJ2c1FnPQ=="
        Response response = Requests.getAuthorizationResponseFromEidasWithSomeUnusedParams(flow, method, flow.domesticConnector.fullEidasResponseUrl, expiredEncodedToken, paramName)
        assertEquals("Correct HTTP status code is returned", statusCode, response.statusCode())
        assertEquals("Correct content type", "application/json", response.getContentType())
        assertThat(response.body().jsonPath().get("incidentNumber"), Matchers.notNullValue())
        assertThat(response.body().jsonPath().get("message").toString(), Matchers.equalTo(message))

        where:
        method            | paramName || statusCode || message
        REQUEST_TYPE_POST | "old"     || 400        || "Token is invalid or has expired"
        REQUEST_TYPE_GET  | "delay"   || 400        || "Token is invalid or has expired"
        REQUEST_TYPE_GET  | "token"   || 400        || "Duplicate request parameter 'token'"
    }

    @Unroll
    @Feature("SAML_RESPONSE_SIGNING")
    def "saml response signed with correct key"() {
        expect:
        String samlRequest = Steps.getAuthnRequest(flow, "eidas-eeserviceprovider")
        Steps.startAuthenticationFlow(flow, REQUEST_TYPE_GET, samlRequest)
        Steps.continueAuthenticationFlow(flow, REQUEST_TYPE_GET)
        Response authenticationResponse = Requests.getAuthorizationResponseFromEidas(flow, REQUEST_TYPE_GET, flow.nextEndpoint, flow.token)
        assertEquals("Correct HTTP status code is returned", 302, authenticationResponse.statusCode())
        Assertion samlAssertion = SamlResponseUtils.extractSamlAssertion(authenticationResponse, flow.domesticSpService.encryptionCredential)
        assertEquals("Correct LOA is returned", "http://eidas.europa.eu/LoA/high", SamlUtils.getLoaValue(samlAssertion))
        String samlResponseXML = SamlResponseUtils.decodeSamlResponse(authenticationResponse)
        SamlSignatureUtils.validateSignature(samlResponseXML, connectorSigningCertificate)
        XmlPath xmlPath = new XmlPath(samlResponseXML).using(new XmlPathConfig("UTF-8"));
        String algorithm = xmlPath.getString("Response.Signature.SignedInfo.SignatureMethod.@Algorithm")
        assertEquals("Correct assertion signing Algoritm", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512", algorithm)
    }

    @Unroll
    @Feature("SAML_ASSERTION_SIGNING")
    def "saml response assertion signed with correct key"() {
        expect:
        String samlRequest = Steps.getAuthnRequest(flow, "eidas-eeserviceprovider")
        Steps.startAuthenticationFlow(flow, REQUEST_TYPE_GET, samlRequest)
        Steps.continueAuthenticationFlow(flow, REQUEST_TYPE_GET)
        Response authenticationResponse = Requests.getAuthorizationResponseFromEidas(flow, REQUEST_TYPE_GET, flow.nextEndpoint, flow.token)
        assertEquals("Correct HTTP status code is returned", 302, authenticationResponse.statusCode())
        Assertion samlAssertion = SamlResponseUtils.extractSamlAssertion(authenticationResponse, flow.domesticSpService.encryptionCredential)
        assertEquals("Correct LOA is returned", "http://eidas.europa.eu/LoA/high", SamlUtils.getLoaValue(samlAssertion))
        SamlSignatureUtils.validateSignature(samlAssertion.getSignature(), connectorSigningCertificate)
        assertEquals("Correct assertion signing Algoritm", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512", samlAssertion.getSignature().getSignatureAlgorithm())
    }

    @Unroll
    @Feature("SAML_ASSERTION_ENCRYPTION")
    def "saml response assertion is encrypted"() {
        expect:
        String spMetadataXml = Requests.getSPMetadataBody(flow)
        XmlPath xmlPath = new XmlPath(spMetadataXml)
        String encryptionCertificate = xmlPath.getString("EntityDescriptor.SPSSODescriptor.KeyDescriptor[1].KeyInfo.X509Data.X509Certificate")
        X509Certificate x509Encryption = X509Support.decodeCertificate(encryptionCertificate)
      //  assertEquals("Correct encryption certificate", x509Encryption, flow.domesticSpService.encryptionCertificate)

        String samlRequest = Steps.getAuthnRequest(flow, "eidas-eeserviceprovider")
        Steps.startAuthenticationFlow(flow, REQUEST_TYPE_GET, samlRequest)
        Steps.continueAuthenticationFlow(flow, REQUEST_TYPE_GET)
        Response authenticationResponse = Requests.getAuthorizationResponseFromEidas(flow, REQUEST_TYPE_GET, flow.nextEndpoint, flow.token)
        assertEquals("Correct HTTP status code is returned", 302, authenticationResponse.statusCode())
        Assertion samlAssertion = SamlResponseUtils.extractSamlAssertion(authenticationResponse, flow.domesticSpService.encryptionCredential)
    }
}
