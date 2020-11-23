package ee.ria.specificconnector

import io.qameta.allure.Allure
import io.qameta.allure.Step
import io.restassured.response.Response
import org.opensaml.saml.saml2.core.AuthnContextComparisonTypeEnumeration
import org.opensaml.saml.saml2.core.AuthnRequest
import org.opensaml.saml.saml2.core.NameIDType
import org.opensaml.security.credential.Credential
import org.spockframework.lang.Wildcard

class Steps {
    static String LOA_HIGH = "http://eidas.europa.eu/LoA/high"
    static String REQUEST_TYPE_POST = "post"
    static String REQUEST_TYPE_GET = "get"

    @Step("Create Natural Person authentication request")
    static String getAuthnRequest(Flow flow, String providerName, String loa = LOA_HIGH, AuthnContextComparisonTypeEnumeration comparison = AuthnContextComparisonTypeEnumeration.MINIMUM, String nameIdFormat = NameIDType.UNSPECIFIED, String spType = "public") {

        AuthnRequest request = new RequestBuilderUtils().buildAuthnRequestParams(flow.domesticSpService.signatureCredential,
                providerName,
                flow.domesticConnector.fullAuthenticationRequestUrl,
                flow.domesticSpService.fullReturnUrl,
                flow.domesticSpService.fullMetadataUrl,
                loa, comparison, nameIdFormat, spType)
        String stringResponse = OpenSAMLUtils.getXmlString(request)
        flow.domesticSpService.samlRequestId = request.getID()
        Allure.addAttachment("Request", "application/xml", stringResponse, "xml")

        SamlSignatureUtils.validateSamlReqSignature(stringResponse)
        return new String(Base64.getEncoder().encode(stringResponse.getBytes()))
    }

    @Step("Create Natural Person authentication request with invalid issuer metadata url")
    static String getAuthnRequestWithInvalidIssuer(Flow flow, String providerName, String loa = LOA_HIGH, AuthnContextComparisonTypeEnumeration comparison = AuthnContextComparisonTypeEnumeration.MINIMUM, String nameIdFormat = NameIDType.UNSPECIFIED, String spType = "public") {

        AuthnRequest request = new RequestBuilderUtils().buildAuthnRequestParams(flow.domesticSpService.signatureCredential,
                providerName,
                flow.domesticConnector.fullAuthenticationRequestUrl,
                flow.domesticSpService.fullReturnUrl,
                "https://example.net/EidasNode/ConnectorMetadata",
                loa, comparison, nameIdFormat, spType)
        String stringResponse = OpenSAMLUtils.getXmlString(request)
        Allure.addAttachment("Request", "application/xml", stringResponse, "xml")

        SamlSignatureUtils.validateSamlReqSignature(stringResponse)
        return new String(Base64.getEncoder().encode(stringResponse.getBytes()))
    }

    @Step("Create Natural Person authentication request without extensions")
    static String getAuthnRequestWithoutExtensions(Flow flow, String providerName, String loa = LOA_HIGH, AuthnContextComparisonTypeEnumeration comparison = AuthnContextComparisonTypeEnumeration.MINIMUM, String nameIdFormat = NameIDType.UNSPECIFIED, String spType = "public") {

        AuthnRequest request = new RequestBuilderUtils().buildAuthnRequestParamsWithoutExtensions(flow.domesticSpService.signatureCredential,
                providerName,
                flow.domesticConnector.fullAuthenticationRequestUrl,
                flow.domesticSpService.fullReturnUrl,
                flow.domesticSpService.fullMetadataUrl,
                loa, comparison, nameIdFormat, spType)
        String stringResponse = OpenSAMLUtils.getXmlString(request)
        Allure.addAttachment("Request", "application/xml", stringResponse, "xml")

        SamlSignatureUtils.validateSamlReqSignature(stringResponse)
        return new String(Base64.getEncoder().encode(stringResponse.getBytes()))
    }

    @Step("Create Natural Person authentication request with unsupported attribute")
    static String getAuthnRequestWithUnsupportedAttribute(Flow flow, String providerName, String loa = LOA_HIGH, AuthnContextComparisonTypeEnumeration comparison = AuthnContextComparisonTypeEnumeration.MINIMUM, String nameIdFormat = NameIDType.UNSPECIFIED, String spType = "public") {

        AuthnRequest request = new RequestBuilderUtils().buildAuthnRequestParamsWithUnsupportedAttribute(flow.domesticSpService.signatureCredential,
                providerName,
                flow.domesticConnector.fullAuthenticationRequestUrl,
                flow.domesticSpService.fullReturnUrl,
                flow.domesticSpService.fullMetadataUrl,
                loa, comparison, nameIdFormat, spType)
        String stringResponse = OpenSAMLUtils.getXmlString(request)
        Allure.addAttachment("Request", "application/xml", stringResponse, "xml")

        SamlSignatureUtils.validateSamlReqSignature(stringResponse)
        return new String(Base64.getEncoder().encode(stringResponse.getBytes()))
    }

    @Step("Create Natural Person authentication request with invalid credential")
    static String getAuthnRequestWithInvalidCredential(Flow flow, String providerName, Credential signingCredential) {

        AuthnRequest request = new RequestBuilderUtils().buildAuthnRequestParams(signingCredential,
                providerName,
                flow.domesticConnector.fullAuthenticationRequestUrl,
                flow.domesticSpService.fullReturnUrl,
                flow.domesticSpService.fullMetadataUrl,
                LOA_HIGH, AuthnContextComparisonTypeEnumeration.MINIMUM, NameIDType.UNSPECIFIED, "public")
        String stringResponse = OpenSAMLUtils.getXmlString(request)
        Allure.addAttachment("Request", "application/xml", stringResponse, "xml")

        SamlSignatureUtils.validateSamlReqSignature(stringResponse)
        return new String(Base64.getEncoder().encode(stringResponse.getBytes()))
    }

    @Step("Create Natural Person authentication request with missing attribute")
    static String getAuthnRequestWithMissingAttribute(Flow flow, String providerName, String attributeName, Object attributeValue) {
        if (attributeValue instanceof Wildcard) {
            attributeValue = null
        }
        AuthnRequest request = new RequestBuilderUtils().buildAuthnRequestWithMissingAttribute(flow.domesticSpService.signatureCredential,
                providerName,
                flow.domesticConnector.fullAuthenticationRequestUrl,
                flow.domesticSpService.fullReturnUrl,
                flow.domesticSpService.fullMetadataUrl,
                LOA_HIGH, AuthnContextComparisonTypeEnumeration.MINIMUM,
                NameIDType.UNSPECIFIED,
                "public",
                attributeName,
                attributeValue,
                flow.domesticSpService.metadataCredential)
        String stringResponse = OpenSAMLUtils.getXmlString(request)
        Allure.addAttachment("Request", "application/xml", stringResponse, "xml")
        if (!attributeName.equals("Signature")) {
            SamlSignatureUtils.validateSamlReqSignature(stringResponse)
        }
        return new String(Base64.getEncoder().encode(stringResponse.getBytes()))
    }

    @Step("Start autentication on domestic country")
    static void startAuthenticationFlow(Flow flow, String requestType, String samlRequest) {
        Response response = Requests.startAuthentication(flow, requestType, samlRequest)
        if (requestType.equals(REQUEST_TYPE_GET)) {
            Response getResponse = Steps.followRedirect(flow, response)
            flow.nextEndpoint = getResponse.body().htmlPath().get("**.find {it.@name == 'redirectForm'}.@action")
            flow.requestMessage = getResponse.body().htmlPath().get("**.find {it.@name == 'redirectForm'}input[0].@value")
            flow.relayState = getResponse.body().htmlPath().get("**.find {it.@id == 'relayState'}.@value")
        } else {
            String lightTokenForRequest = response.getBody().htmlPath().getString("**.find { it.@name == 'token' }.@value")
            String lightTokenRequestUrl = response.getBody().htmlPath().getString("**.find { it.@method == 'post' }.@action")
            Response postResponse = Requests.sendLightTokenRequestToEidas(flow, lightTokenRequestUrl, lightTokenForRequest)
            flow.nextEndpoint = postResponse.body().htmlPath().get("**.find {it.@name == 'redirectForm'}.@action")
            flow.requestMessage = postResponse.getBody().htmlPath().getString("**.findAll { it.@name == 'SAMLRequest' }[0].@value")
            flow.relayState = postResponse.body().htmlPath().get("**.find {it.@id == 'relayState'}.@value")
        }
    }

    @Step("Continue authentication on abroad")
    static void continueAuthenticationFlow(Flow flow, String requestType, String idpUsername = "xavi", idpPassword = "creus" , String eidasloa = "E") {
        Response response2 = Requests.colleagueRequest(flow, requestType, flow.requestMessage, flow.nextEndpoint)
        String action = response2.body().htmlPath().get("**.find {it.@id == 'redirectForm'}.@action")
        String token = response2.body().htmlPath().get("**.find {it.@id == 'redirectForm'}.input[0].@value")

        Response response3 = Requests.proxyServiceRequest(flow, requestType, action, token)
        String action2 = response3.body().htmlPath().get("**.find {it.@name == 'redirectForm'}.@action")
        String smsspRequest = response3.body().htmlPath().get("**.find {it.@id == 'SMSSPRequest'}.@value")
        Response response4 = Requests.idpRequest(flow, requestType, action2, smsspRequest)
        String smsspToken = response4.body().htmlPath().get("**.find {it.@name == 'smsspToken'}.@value")
        String smsspTokenRequestJson = response4.body().htmlPath().get("**.find {it.@id == 'jSonRequestDecoded'}")

        Response response5 = Requests.idpAuthorizationRequest(flow, smsspToken, smsspTokenRequestJson, idpUsername, idpPassword, eidasloa)
        String action3 = response5.body().htmlPath().get("**.find {it.@name == 'redirectForm'}.@action")
        String smsspTokenResponse = response5.body().htmlPath().get("**.find {it.@id == 'SMSSPResponseNoJS'}.@value")

        Response response6 = Requests.idpAuthorizationResponse(flow, action3, smsspTokenResponse)
        String binaryLightToken = response6.body().htmlPath().get("**.find {it.@id == 'binaryLightToken'}.@value")

        Response response7 = Requests.afterCitizenConsentResponse(flow, binaryLightToken)
        String action5 = response7.body().htmlPath().get("**.find {it.@id == 'redirectForm'}.@action")
        String token2 = response7.body().htmlPath().get("**.find {it.@id == 'token'}.@value")

        Response response8 = Requests.proxyServiceRequest(flow, requestType, action5, token2)
        String samlResponse = response8.body().htmlPath().get("**.find {it.@id == 'ColleagueResponse_SAMLResponse'}.@value")

        Response response9 = Requests.colleagueResponse(flow, samlResponse)
        flow.token = response9.body().htmlPath().get("**.find {it.@id == 'token'}.@value")
        flow.nextEndpoint = response9.body().htmlPath().get("**.find {it.@name == 'redirectForm'}.@action")
    }

    @Step("Continue authentication on abroad with errors")
    static void continueAuthenticationFlowWithErrors(Flow flow, String requestType, String idpUsername = "xavi", idpPassword = "creus" , String eidasloa = "E") {
        Response response2 = Requests.colleagueRequest(flow, requestType, flow.requestMessage, flow.nextEndpoint)
        String action = response2.body().htmlPath().get("**.find {it.@id == 'redirectForm'}.@action")
        String token = response2.body().htmlPath().get("**.find {it.@id == 'redirectForm'}.input[0].@value")

        Response response3 = Requests.proxyServiceRequest(flow, requestType, action, token)
        String action2 = response3.body().htmlPath().get("**.find {it.@name == 'redirectForm'}.@action")
        String smsspRequest = response3.body().htmlPath().get("**.find {it.@id == 'SMSSPRequest'}.@value")
        Response response4 = Requests.idpRequest(flow, requestType, action2, smsspRequest)
        String smsspToken = response4.body().htmlPath().get("**.find {it.@name == 'smsspToken'}.@value")
        String smsspTokenRequestJson = response4.body().htmlPath().get("**.find {it.@id == 'jSonRequestDecoded'}")

        Response response5 = Requests.idpAuthorizationRequest(flow, smsspToken, smsspTokenRequestJson, idpUsername, idpPassword, eidasloa)
        String action3 = response5.body().htmlPath().get("**.find {it.@name == 'redirectForm'}.@action")
        String smsspTokenResponse = response5.body().htmlPath().get("**.find {it.@id == 'SMSSPResponseNoJS'}.@value")

        Response response6 = Requests.idpAuthorizationResponse(flow, action3, smsspTokenResponse)
        String binaryLightToken = response6.body().htmlPath().get("**.find {it.@id == 'binaryLightToken'}.@value")

        Response response7 = Requests.afterCitizenConsentResponse(flow, binaryLightToken)
        String action5 = response7.body().htmlPath().get("**.find {it.@id == 'redirectForm'}.@action")
        String token2 = response7.body().htmlPath().get("**.find {it.@id == 'token'}.@value")

        Response response8 = Requests.proxyServiceRequest(flow, requestType, action5, token2)
        String samlResponse = response8.body().htmlPath().get("**.find {it.@id == 'SAMLResponse'}.@value")

        Response response9 = Requests.colleagueResponse(flow, samlResponse)
        flow.token = response9.body().htmlPath().get("**.find {it.@id == 'token'}.@value")
        flow.nextEndpoint = response9.body().htmlPath().get("**.find {it.@name == 'redirectForm'}.@action")
    }

    @Step("Continue authentication on abroad deny consent")
    static String continueAuthenticationFlowDenyConsent(Flow flow, String requestType) {
        Response response2 = Requests.colleagueRequest(flow, requestType, flow.requestMessage, flow.nextEndpoint)
        String action = response2.body().htmlPath().get("**.find {it.@id == 'redirectForm'}.@action")
        String token = response2.body().htmlPath().get("**.find {it.@id == 'redirectForm'}.input[0].@value")

        Response response3 = Requests.proxyServiceRequest(flow, requestType, action, token)
        String action2 = response3.body().htmlPath().get("**.find {it.@name == 'redirectForm'}.@action")
        String smsspRequest = response3.body().htmlPath().get("**.find {it.@id == 'SMSSPRequest'}.@value")
        Response response4 = Requests.idpRequest(flow, requestType, action2, smsspRequest)
        String smsspToken = response4.body().htmlPath().get("**.find {it.@name == 'smsspToken'}.@value")
        String smsspTokenRequestJson = response4.body().htmlPath().get("**.find {it.@id == 'jSonRequestDecoded'}")

        Response response5 = Requests.idpAuthorizationRequest(flow, smsspToken, smsspTokenRequestJson)
        String action3 = response5.body().htmlPath().get("**.find {it.@name == 'redirectForm'}.@action")
        String smsspTokenResponse = response5.body().htmlPath().get("**.find {it.@id == 'SMSSPResponseNoJS'}.@value")

        Response response6 = Requests.idpAuthorizationResponse(flow, action3, smsspTokenResponse)
        String binaryLightToken = response6.body().htmlPath().get("**.find {it.@id == 'binaryLightToken'}.@value")

        Response response7 = Requests.denyConsentResponse(flow, binaryLightToken)
        String action5 = response7.body().htmlPath().get("**.find {it.@id == 'redirectForm'}.@action")
        String token2 = response7.body().htmlPath().get("**.find {it.@id == 'token'}.@value")

        Response response8 = Requests.proxyServiceRequest(flow, requestType, action5, token2)
        return response8.body().htmlPath().getString("**.find {it.@id == 'ColleagueResponse_SAMLResponse'}.@value")
    }

    @Step("Follow redirect")
    static Response followRedirect(Flow flow, Response response) {
        String location = response.then().extract().response().getHeader("location")

        return Requests.followRedirect(flow, location)
    }
}
