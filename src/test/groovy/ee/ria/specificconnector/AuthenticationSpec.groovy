package ee.ria.specificconnector

import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.path.xml.XmlPath
import io.restassured.response.Response
import org.apache.http.HttpStatus
import org.opensaml.saml.saml2.core.AuthnContextComparisonTypeEnumeration

import static org.hamcrest.CoreMatchers.*
import static org.hamcrest.Matchers.containsInAnyOrder
import org.opensaml.saml.saml2.core.Assertion
import spock.lang.Unroll

import static org.junit.Assert.assertEquals
import static org.junit.Assert.assertThat
import org.apache.commons.lang.RandomStringUtils
import java.nio.charset.StandardCharsets
import static org.junit.Assert.assertTrue
import static ee.ria.specificconnector.ResponseAssertions.assertErrorEnvelope
import static ee.ria.specificconnector.ResponseAssertions.assertSecurityHeaders


class AuthenticationSpec extends EEConnectorSpecification {

    // one char over the RelayState limit
    static final String OVER_LENGTH_RELAY_STATE = "1XyyAocKwZp8Zp8qd9lhVKiJPF1AywyfpXTLqYGLFE73CKcEgSKOrfVq9UMfX9HAfWwBJMI9O7Bm22BZ1"

    Flow flow = new Flow(props)

    def setup() {
        flow.domesticSpService.signatureCredential = signatureCredential
        flow.domesticSpService.encryptionCredential = encryptionCredential
        flow.domesticSpService.metadataCredential = metadataCredential
        flow.domesticSpService.expiredCredential = expiredCredential
        flow.domesticSpService.unsupportedCredential = unsupportedCredential
        flow.domesticSpService.unsupportedByConfigurationCredential = unsupportedByConfigurationCredential
        flow.cookieFilter = new CookieFilter()
    }

    @Unroll
    @Feature("AUTHENTICATION_SAMLREQUEST_VALID_SIGNATURE")
    def "request authentication with post, public SPType"() {
        expect:
        String samlRequest = Steps.getAuthnRequest(flow)

        Response response = Requests.startAuthentication(flow, REQUEST_TYPE_POST, samlRequest)
        assertThat(response.getStatusCode(), equalTo(200))
        String lightTokenForRequest = response.getBody().htmlPath().getString("**.find { it.@name == 'token' }.@value")
        String lightTokenRequestUrl = response.getBody().htmlPath().getString("**.find { it.@method == 'post' }.@action")

        Response response1 = Requests.sendLightTokenRequestToEidas(flow, lightTokenRequestUrl, lightTokenForRequest)
        flow.setRequestMessage(response1.getBody().htmlPath().getString("**.findAll { it.@name == 'SAMLRequest' }[0].@value"))
        flow.setNextEndpoint(response1.body().htmlPath().get("**.find {it.@name == 'redirectForm'}.@action"))

        Steps.continueAuthenticationFlow(flow, REQUEST_TYPE_POST)

        Response response10 = Requests.getAuthorizationResponseFromEidas(flow, REQUEST_TYPE_POST, flow.nextEndpoint, flow.token)
        assertEquals("Correct HTTP status code is returned", 200, response10.statusCode())
        Assertion samlAssertion = SamlResponseUtils.extractSamlAssertionFromPost(response10, flow.domesticSpService.encryptionCredential)
        assertEquals("Correct LOA is returned", "http://eidas.europa.eu/LoA/high", SamlUtils.getLoaValue(samlAssertion))
    }

    @Unroll
    @Feature("AUTHENTICATION_SAMLREQUEST_VALID_SIGNATURE")
    def "request authentication with post, private SPType"() {
        expect:
        String samlRequest = Steps.getAuthnRequestWithSpType(flow, "private")

        Response response = Requests.startAuthentication(flow, REQUEST_TYPE_POST, samlRequest)
        assertThat(response.getStatusCode(), equalTo(200))
        String lightTokenForRequest = response.getBody().htmlPath().getString("**.find { it.@name == 'token' }.@value")
        String lightTokenRequestUrl = response.getBody().htmlPath().getString("**.find { it.@method == 'post' }.@action")

        Response response1 = Requests.sendLightTokenRequestToEidas(flow, lightTokenRequestUrl, lightTokenForRequest)
        flow.setRequestMessage(response1.getBody().htmlPath().getString("**.findAll { it.@name == 'SAMLRequest' }[0].@value"))
        flow.setNextEndpoint(response1.body().htmlPath().get("**.find {it.@name == 'redirectForm'}.@action"))

        Steps.continueAuthenticationFlow(flow, REQUEST_TYPE_POST)

        Response response10 = Requests.getAuthorizationResponseFromEidas(flow, REQUEST_TYPE_POST, flow.nextEndpoint, flow.token)
        assertEquals("Correct HTTP status code is returned", 200, response10.statusCode())
        Assertion samlAssertion = SamlResponseUtils.extractSamlAssertionFromPost(response10, flow.domesticSpService.encryptionCredential)
        assertEquals("Correct LOA is returned", "http://eidas.europa.eu/LoA/high", SamlUtils.getLoaValue(samlAssertion))
    }

    @Unroll
    @Feature("AUTHENTICATION_SAMLREQUEST_VALID_SIGNATURE")
    def "request authentication with get, public SPType"() {
        expect:
        String samlRequest = Steps.getAuthnRequest(flow)
        String relayState = "ABC-" + RandomStringUtils.random(76, true, true)

        Response response = Requests.startAuthentication(flow, REQUEST_TYPE_GET, samlRequest, "RelayState", relayState)
        assertEquals("Correct HTTP status code is returned", 302, response.statusCode())
        Response response1 = Steps.followRedirect(flow, response)
        flow.setNextEndpoint(response1.body().htmlPath().get("**.find {it.@name == 'redirectForm'}.@action"))
        flow.setRequestMessage(response1.body().htmlPath().get("**.find {it.@name == 'redirectForm'}input[0].@value"))

        Steps.continueAuthenticationFlow(flow, REQUEST_TYPE_GET)

        Response response10 = Requests.getAuthorizationResponseFromEidas(flow, REQUEST_TYPE_GET, flow.nextEndpoint, flow.token)
        assertEquals("Correct HTTP status code is returned", 302, response10.statusCode())
        Assertion samlAssertion = SamlResponseUtils.extractSamlAssertion(response10, flow.domesticSpService.encryptionCredential)
        assertEquals("Correct LOA is returned", "http://eidas.europa.eu/LoA/high", SamlUtils.getLoaValue(samlAssertion))
    }

    @Unroll
    @Feature("AUTHENTICATION_SAMLREQUEST_VALID_SIGNATURE")
    def "request authentication with get, private SPType"() {
        expect:
        String samlRequest = Steps.getAuthnRequestWithSpType(flow, "private")
        String relayState = "ABC-" + RandomStringUtils.random(76, true, true)

        Response response = Requests.startAuthentication(flow, REQUEST_TYPE_GET, samlRequest, "RelayState", relayState)
        assertEquals("Correct HTTP status code is returned", 302, response.statusCode())
        Response response1 = Steps.followRedirect(flow, response)
        flow.setNextEndpoint(response1.body().htmlPath().get("**.find {it.@name == 'redirectForm'}.@action"))
        flow.setRequestMessage(response1.body().htmlPath().get("**.find {it.@name == 'redirectForm'}input[0].@value"))

        Steps.continueAuthenticationFlow(flow, REQUEST_TYPE_GET)

        Response response10 = Requests.getAuthorizationResponseFromEidas(flow, REQUEST_TYPE_GET, flow.nextEndpoint, flow.token)
        assertEquals("Correct HTTP status code is returned", 302, response10.statusCode())
        Assertion samlAssertion = SamlResponseUtils.extractSamlAssertion(response10, flow.domesticSpService.encryptionCredential)
        assertEquals("Correct LOA is returned", "http://eidas.europa.eu/LoA/high", SamlUtils.getLoaValue(samlAssertion))
    }

    @Unroll
    @Feature("AUTHENTICATION_REQUEST_ATTRIBUTES_CHECK")
    def "validate authentication request SAML elements, SPType #spType"() {
        expect:
        String samlRequest = Steps.getAuthnRequestWithSpType(flow, spType)

        Response response = Requests.startAuthentication(flow, REQUEST_TYPE_POST, samlRequest)

        String lightTokenForRequest = response.getBody().htmlPath().getString("**.find { it.@name == 'token' }.@value")
        String lightTokenRequestUrl = response.getBody().htmlPath().getString("**.find { it.@method == 'post' }.@action")

        Response response1 = Requests.sendLightTokenRequestToEidas(flow, lightTokenRequestUrl, lightTokenForRequest)

        String samlToken = response1.getBody().htmlPath().getString("**.findAll { it.@name == 'SAMLRequest' }[0].@value")
        String redirectUrl = response1.getBody().htmlPath().getString("**.findAll { it.@name == 'redirectFormNoJs' }[0].@action")

        String samlResponse = SamlUtils.decodeBase64(samlToken)
        XmlPath xmlPath = new XmlPath(samlResponse)

        String destination = xmlPath.getString("AuthnRequest.@Destination")
        String forceAuthn = xmlPath.getString("AuthnRequest.@ForceAuthn")
        String isPassive = xmlPath.getString("AuthnRequest.@IsPassive")
        String providerName = xmlPath.getString("AuthnRequest.@ProviderName")
        String version = xmlPath.getString("AuthnRequest.@Version")
        String issuer = xmlPath.getString("AuthnRequest.Issuer")
        String issuerFormat = xmlPath.getString("AuthnRequest.Issuer.@Format")
        String digest = xmlPath.getString("AuthnRequest.Signature.SignedInfo.Reference.DigestValue")
        String signatureValue = xmlPath.getString("AuthnRequest.Signature.SignatureValue")
        String certificate = xmlPath.getString("AuthnRequest.Signature.KeyInfo.X509Data.X509Certificate")
        String allowCreate = xmlPath.getString("AuthnRequest.NameIDPolicy.@AllowCreate")
        String comparison = xmlPath.getString("AuthnRequest.RequestedAuthnContext.@Comparison")
        String authnContextClassRef = xmlPath.getString("AuthnRequest.RequestedAuthnContext.AuthnContextClassRef")
        String serviceProviderType = xmlPath.getString("AuthnRequest.Extensions.SPType")
        List<String> requestedAttributes = xmlPath.getList("AuthnRequest.Extensions.RequestedAttributes.RequestedAttribute.@FriendlyName")
        String isRequired = xmlPath.getString("AuthnRequest.Extensions.RequestedAttributes.RequestedAttribute.@isRequired")
        String requesterID = xmlPath.getString("AuthnRequest.Scoping.RequesterID")

        assertEquals("Correct Destination URL is returned", redirectUrl, destination)
        assertEquals("Correct ForceAuthn value is returned", "true", forceAuthn)
        assertEquals("Correct IsPassive value is returned", "false", isPassive)
        assertEquals("Correct providerName is returned", flow.domesticSpService.providerName.toString(), providerName)
        assertEquals("Correct version is returned", "2.0", version)
        assertEquals("Correct issuer is returned", flow.domesticConnector.fullEidasNodeMetadataUrl.toString(), issuer)
        assertEquals("Correct issuerFormat is returned", "urn:oasis:names:tc:SAML:2.0:nameid-format:entity", issuerFormat)
        assertThat("Digest is present", digest, notNullValue())
        assertThat("Signature is present", signatureValue, notNullValue())
        assertThat("Certificate is present", certificate, notNullValue())
        assertEquals("Correct SPType is returned", spType, serviceProviderType)
        assertThat("Correct RequestedAttributes are returned", requestedAttributes,
                containsInAnyOrder("PersonIdentifier", "FamilyName", "FirstName", "DateOfBirth"))
        assertThat("RequesterAttributes are required", isRequired, not(containsString(("false"))))
        assertEquals("Correct AllowCreate value is returned", "true", allowCreate)
        assertEquals("Correct RequestedAuthnContext comparison value is returned", "minimum", comparison)
        assertThat("AuthnContextClassRef is present", authnContextClassRef, notNullValue())
        assertEquals("Correct RequesterID is returned", requester, requesterID)

        where:
        spType    | requester
        "public"  | ""
        "private" | "TEST-REQUESTER-ID"
    }

    @Unroll
    @Feature("AUTHENTICATION_ENDPOINT")
    def "request authentication with multiple instances"() {
        expect:
        Response response = Requests.startAuthenticationWithDuplicateParams(flow, REQUEST_TYPE_POST, "1234567", additionalParam, "78901234")
        assertErrorEnvelope(response, statusCode, flow.domesticConnector.authenticationRequestUrl)
        assertThat(response.body().jsonPath().getString("message"), equalTo(message))

        where:
        additionalParam || statusCode                | message
        "SAMLRequest"   || HttpStatus.SC_BAD_REQUEST | "Duplicate request parameter 'SAMLRequest'"
        "country"       || HttpStatus.SC_BAD_REQUEST | "Duplicate request parameter 'country'"
        "RelayState"    || HttpStatus.SC_BAD_REQUEST | "Duplicate request parameter 'RelayState'"
    }

    @Unroll
    @Feature("AUTHENTICATION_ENDPOINT")
    def "request authentication with invalid parameters. Expected error message: [#messageMatcher]"() {
        expect:
        String samlRequest = Steps.getAuthnRequest(flow)
        def map = [:]
        // Spock specific workaround
        def map1 = SamlUtils.setUrlParameter(map, param1, samlRequest)
        def map2 = SamlUtils.setUrlParameter(map, param2, param2Value)
        def map3 = SamlUtils.setUrlParameter(map, param3, param3Value)

        Response response = Requests.startAuthenticationWithParameters(flow, REQUEST_TYPE_POST, map)
        assertErrorEnvelope(response, statusCode, flow.domesticConnector.authenticationRequestUrl)
        assertThat(response.body().jsonPath().getString("message"), messageMatcher)

        where:
        // startsWith only where the message ends with the production @Pattern regex
        param1        | param2        | param2Value | param3       | param3Value             || statusCode                | messageMatcher
        _             | _             | _           | _            | _                       || HttpStatus.SC_BAD_REQUEST | equalTo("Required request parameter 'SAMLRequest' for method parameter type String is not present")
        "SAMLRequest" | _             | _           | _            | _                       || HttpStatus.SC_BAD_REQUEST | equalTo("Required request parameter 'country' for method parameter type String is not present")
        "SAMLRequest" | "country"     | _           | _            | _                       || HttpStatus.SC_BAD_REQUEST | startsWith("post.country: must match ")
        "SAMLRequest" | "country"     | "CAA"       | _            | _                       || HttpStatus.SC_BAD_REQUEST | startsWith("post.country: must match ")
        "SAMLRequest" | "country"     | "CA"        | "RelayState" | OVER_LENGTH_RELAY_STATE || HttpStatus.SC_BAD_REQUEST | startsWith("post.RelayState: must match")
        "SAMLRequest" | "country"     | "CA"        | "RelayState" | "\b\f"                  || HttpStatus.SC_BAD_REQUEST | startsWith("post.RelayState: must match")
        _             | "SAMLRequest" | "Ää"        | "country"    | "CA"                    || HttpStatus.SC_BAD_REQUEST | startsWith("post.SAMLRequest: must match")
    }

    @Unroll
    @Feature("AUTHENTICATION_REQUEST_SP_CHECK")
    def "request authentication with invalid service provider"() {
        expect:
        String samlRequest = Steps.getAuthnRequestWithInvalidIssuer(flow)
        Response response = Requests.startAuthentication(flow, REQUEST_TYPE_GET, samlRequest)
        assertErrorEnvelope(response, HttpStatus.SC_BAD_REQUEST, flow.domesticConnector.authenticationRequestUrl)
        assertThat(response.body().jsonPath().getString("message"), equalTo("SAML request is invalid - issuer not allowed"))
    }

    @Unroll
    @Feature("AUTHENTICATION_REQUEST_SP_CHECK")
    def "request authentication with invalid level of assurance: comparison type minimum and loa #loa"() {
        expect:
        String samlRequest = Steps.getAuthnRequestWithLoa(flow, loa, AuthnContextComparisonTypeEnumeration.MINIMUM)
        Response response = Requests.startAuthentication(flow, REQUEST_TYPE_GET, samlRequest)
        assertErrorEnvelope(response, statusCode, flow.domesticConnector.authenticationRequestUrl)
        assertThat(response.body().jsonPath().getString("message"), equalTo(message))

        where:
        loa              | statusCode                          | message
        ""               | HttpStatus.SC_INTERNAL_SERVER_ERROR | "Something went wrong internally. Please consult server logs for further details."
        "LOA_INVALID"    | HttpStatus.SC_BAD_REQUEST           | "SAML request is invalid - invalid Level of Assurance"
        LOA_NON_NOTIFIED | HttpStatus.SC_BAD_REQUEST           | "SAML request is invalid - invalid Level of Assurance"
    }

    @Unroll
    @Feature("AUTHENTICATION_REQUEST_SP_CHECK")
    def "request authentication with invalid level of assurance: comparison type exact and loa #loa"() {
        expect:
        String samlRequest = Steps.getAuthnRequestWithLoa(flow, loa, AuthnContextComparisonTypeEnumeration.EXACT)
        Response response = Requests.startAuthentication(flow, REQUEST_TYPE_GET, samlRequest)
        assertErrorEnvelope(response, statusCode, flow.domesticConnector.authenticationRequestUrl)
        assertThat(response.body().jsonPath().getString("message"), equalTo(message))

        where:
        loa           | statusCode                          | message
        ""            | HttpStatus.SC_INTERNAL_SERVER_ERROR | "Something went wrong internally. Please consult server logs for further details."
        "LOA_INVALID" | HttpStatus.SC_INTERNAL_SERVER_ERROR | "Something went wrong internally. Please consult server logs for further details."
    }

    @Unroll
    @Feature("AUTHENTICATION_REQUEST_ATTRIBUTES_CHECK")
    def "request authentication with missing attributes"() {
        expect:
        String samlRequest = Steps.getAuthnRequestWithoutExtensions(flow)
        Response response = Requests.startAuthentication(flow, REQUEST_TYPE_GET, samlRequest)
        assertErrorEnvelope(response, HttpStatus.SC_BAD_REQUEST, flow.domesticConnector.authenticationRequestUrl)
        assertThat(response.body().jsonPath().getString("message"), equalTo("SAML request is invalid - no requested attributes"))
    }

    @Unroll
    @Feature("AUTHENTICATION_REQUEST_ATTRIBUTES_CHECK")
    def "request authentication with unsupported attribute"() {
        expect:
        String samlRequest = Steps.getAuthnRequestWithUnsupportedAttribute(flow)
        Response response = Requests.startAuthentication(flow, REQUEST_TYPE_GET, samlRequest)
        assertErrorEnvelope(response, HttpStatus.SC_BAD_REQUEST, flow.domesticConnector.authenticationRequestUrl)
        assertThat(response.body().jsonPath().getString("message"), equalTo("SAML request is invalid - unsupported requested attributes"))
    }

    @Unroll
    @Feature("AUTHENTICATION_SAMLREQUEST_VALID_SIGNATURE")
    def "request authentication with invalid signing certificate #credential.entityId"() {
        expect:
        String samlRequest = Steps.getAuthnRequestWithInvalidCredential(flow, credential)
        Response response = Requests.startAuthentication(flow, REQUEST_TYPE_GET, samlRequest)
        assertErrorEnvelope(response, statusCode, flow.domesticConnector.authenticationRequestUrl)
        assertThat(response.body().jsonPath().getString("message"), equalTo("SAML request is invalid - invalid signature"))

        where:
        credential                           || statusCode
        metadataCredential                   || HttpStatus.SC_BAD_REQUEST
        expiredCredential                    || HttpStatus.SC_BAD_REQUEST
        unsupportedCredential                || HttpStatus.SC_BAD_REQUEST
        unsupportedByConfigurationCredential || HttpStatus.SC_BAD_REQUEST
    }

    @Unroll
    @Feature("AUTHENTICATION_REQUEST_VALIDATION")
    @Feature("SECURITY")
    def "request authentication is rejected by #rejectedBy when the URI contains #description"() {
        expect:
        Response response = Requests.startAuthenticationWithRawPath(flow, REQUEST_TYPE_GET, rawPathSuffix)

        assertThat("Correct HTTP status code is returned", response.statusCode(), equalTo(HttpStatus.SC_BAD_REQUEST))

        where:
        rejectedBy           | description        | rawPathSuffix
        "Tomcat"             | "an encoded slash" | "%2f"
        "StrictHttpFirewall" | "a double slash"   | "//"
    }

    @Unroll
    @Feature("AUTHENTICATION_REQUEST_VALIDATION")
    def "request authentication GET with invalid saml request. #attributeName"() {
        expect:
        String samlRequest = Steps.getAuthnRequestWithMissingAttribute(flow, attributeName, attributeValue)

        Response response = Requests.startAuthentication(flow, REQUEST_TYPE_GET, samlRequest)
        assertErrorEnvelope(response, HttpStatus.SC_BAD_REQUEST, flow.domesticConnector.authenticationRequestUrl)
        assertThat(response.body().jsonPath().getString("message"), equalTo(message))

        where:
        attributeName  | attributeValue                                     || message
        "IsPassive"    | true                                               || "SAML request is invalid - expecting IsPassive to be false"
        "ForceAuthn"   | _                                                  || "SAML request is invalid - expecting ForceAuthn to be true"
        "ForceAuthn"   | false                                              || "SAML request is invalid - expecting ForceAuthn to be true"
        "ID"           | _                                                  || "SAML request is invalid - does not conform to schema"
        "ID"           | "31"                                               || "SAML request is invalid - does not conform to schema"
        "IssueInstant" | _                                                  || "SAML request is invalid - does not conform to schema"
        "Version"      | _                                                  || "SAML request is invalid - expecting SAML Version to be 2.0"
        "Version"      | "3.0"                                              || "SAML request is invalid - expecting SAML Version to be 2.0"
        "Issuer"       | _                                                  || "SAML request is invalid - missing issuer"
        "Issuer"       | "https://example.org/metadata"                     || "SAML request is invalid - issuer not allowed"
        "Signature"    | _                                                  || "SAML request is invalid - invalid signature"
        "Signature"    | "value"                                            || "SAML request is invalid - invalid signature"
        "RequesterID"  | _                                                  || "SAML request is invalid - no RequesterID"
        "SPType"       | _                                                  || "SAML request is invalid - no SPType"
        "SPType"       | "voluntary"                                        || "SAML request is invalid - does not conform to schema"
        "NameIDPolicy" | "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"  || "SAML request is invalid - invalid NameIDPolicy"
        "NameIDPolicy" | "urn:oasis:names:tc:SAML:2.0:nameid-format:entity" || "SAML request is invalid - invalid NameIDPolicy"
    }

    @Unroll
    @Feature("AUTHENTICATION_REQUEST_VALIDATION")
    def "request authentication POST with invalid saml request. #attributeName"() {
        expect:
        String samlRequest = Steps.getAuthnRequestWithMissingAttribute(flow, attributeName, attributeValue)

        Response response = Requests.startAuthentication(flow, REQUEST_TYPE_POST, samlRequest)
        assertErrorEnvelope(response, HttpStatus.SC_BAD_REQUEST, flow.domesticConnector.authenticationRequestUrl)
        assertThat(response.body().jsonPath().getString("message"), equalTo(message))

        where:
        attributeName  | attributeValue                                     || message
        "IsPassive"    | true                                               || "SAML request is invalid - expecting IsPassive to be false"
        "ForceAuthn"   | _                                                  || "SAML request is invalid - expecting ForceAuthn to be true"
        "ForceAuthn"   | false                                              || "SAML request is invalid - expecting ForceAuthn to be true"
        "ID"           | _                                                  || "SAML request is invalid - does not conform to schema"
        "ID"           | "31"                                               || "SAML request is invalid - does not conform to schema"
        "IssueInstant" | _                                                  || "SAML request is invalid - does not conform to schema"
        "Version"      | _                                                  || "SAML request is invalid - expecting SAML Version to be 2.0"
        "Version"      | "3.0"                                              || "SAML request is invalid - expecting SAML Version to be 2.0"
        "Issuer"       | _                                                  || "SAML request is invalid - missing issuer"
        "Issuer"       | "https://example.org/metadata"                     || "SAML request is invalid - issuer not allowed"
        "Signature"    | _                                                  || "SAML request is invalid - invalid signature"
        "Signature"    | "value"                                            || "SAML request is invalid - invalid signature"
        "RequesterID"  | _                                                  || "SAML request is invalid - no RequesterID"
        "SPType"       | _                                                  || "SAML request is invalid - no SPType"
        "SPType"       | "voluntary"                                        || "SAML request is invalid - does not conform to schema"
        "NameIDPolicy" | "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"  || "SAML request is invalid - invalid NameIDPolicy"
        "NameIDPolicy" | "urn:oasis:names:tc:SAML:2.0:nameid-format:entity" || "SAML request is invalid - invalid NameIDPolicy"
    }

    @Unroll
    @Feature("AUTHENTICATION_REQUEST_VALIDATION")
    def "request authentication with missing parameters #attributeName"() {
        expect:
        String samlRequest = Steps.getAuthnRequestWithMissingAttribute(flow, attributeName, attributeValue)
        print samlRequest.size()
        Response response = Requests.startAuthentication(flow, REQUEST_TYPE_POST, samlRequest)
        assertEquals("Correct HTTP status code is returned", 200, response.statusCode())

        where:
        attributeName  | attributeValue
        "ProviderName" | "illegal-provider"
        "ProviderName" | _
        "ProviderName" | RandomStringUtils.random(93500, true, true)
        "IssueInstant" | "2030-11-08T19:29:47.759Z"
    }

    @Unroll
    @Feature("AUTHENTICATION_SAMLREQUEST_CREATE_LIGHTTOKEN")
    @Feature("AUTHENTICATION_REDIRECT_WITH_LIGHTTOKEN")
    def "request authentication with LightToken and post"() {
        expect:
        String samlRequest = Steps.getAuthnRequest(flow)
        Response response = Requests.startAuthentication(flow, REQUEST_TYPE_POST, samlRequest)
        assertEquals("Correct HTTP status code is returned", 200, response.statusCode())
        String lightTokenRequestUrl = response.getBody().htmlPath().getString("**.find { it.@method == 'post' }.@action")
        assertThat(lightTokenRequestUrl, containsStringIgnoringCase("/EidasNode/SpecificConnectorRequest"))
        String htmlBody = response.getBody().prettyPrint()
        assertTrue(htmlBody.contains("</noscript>"))

        String encodedToken = response.body().htmlPath().get("**.find {it.@name == 'token'}.@value")
        String[] lightToken = new String(Base64.getDecoder().decode(encodedToken), StandardCharsets.UTF_8).split("\\|")
        assertEquals("Correct IssuerName in lightToken", "specificCommunicationDefinitionConnectorRequest", lightToken[0])
        assertTrue(SamlUtils.isValidUUID(lightToken[1]))
        assertTrue(SamlUtils.isValidDateTime(lightToken[2]))
        assertThat(Base64.getDecoder().decode(lightToken[3]).size(), equalTo(32))
        assertEquals("Correct Content-Type is returned", "text/html;charset=UTF-8", response.getContentType())
    }

    @Unroll
    @Feature("AUTHENTICATION_SAMLREQUEST_CREATE_LIGHTTOKEN")
    @Feature("AUTHENTICATION_REDIRECT_WITH_LIGHTTOKEN")
    def "request authentication redirect with LightToken and get"() {
        expect:
        String samlRequest = Steps.getAuthnRequest(flow)
        String relayState = "CDE-" + RandomStringUtils.random(76, true, true)

        Response response = Requests.startAuthentication(flow, REQUEST_TYPE_GET, samlRequest, "RelayState", relayState)
        assertEquals("Correct HTTP status code is returned", 302, response.statusCode())
        URL locationUrl = response.then().extract().response().getHeader("location").toURL()
        String[] locationQuery = locationUrl.getQuery().split("=")
        assertEquals("Correct location attribute name", "token", locationQuery[0])
        assertThat(locationUrl.getPath(), containsStringIgnoringCase("/EidasNode/SpecificConnectorRequest"))

        String[] lightToken = new String(Base64.getDecoder().decode(locationQuery[1]), StandardCharsets.UTF_8).split("\\|")
        assertEquals("Correct IssuerName in lightToken", "specificCommunicationDefinitionConnectorRequest", lightToken[0])
        assertTrue(SamlUtils.isValidUUID(lightToken[1]))
        assertTrue(SamlUtils.isValidDateTime(lightToken[2]))
        assertThat(Base64.getDecoder().decode(lightToken[3]).size(), equalTo(32))
    }

    @Unroll
    @Feature("AUTHENTICATION_ENDPOINT")
    @Feature("SECURITY")
    def "Verify authentication response header"() {
        expect:
        String samlRequest = Steps.getAuthnRequest(flow)
        Response response = Requests.startAuthentication(flow, REQUEST_TYPE_GET, samlRequest)
        response.then().header("Content-Security-Policy", is(defaultContentSecurityPolicy))
        assertSecurityHeaders(response)
    }
}
