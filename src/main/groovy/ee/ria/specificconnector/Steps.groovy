package ee.ria.specificconnector

import ee.ria.specificconnector.tara.MobileId
import io.qameta.allure.Allure
import io.qameta.allure.Step
import io.restassured.response.Response
import org.opensaml.saml.saml2.core.AuthnContextComparisonTypeEnumeration
import org.opensaml.saml.saml2.core.AuthnRequest
import org.opensaml.saml.saml2.core.NameIDType

class Steps {
    static String LOA_HIGH = "http://eidas.europa.eu/LoA/high"

    static String getAuthnRequestWithDefault(Flow flow) {
        return getAuthnRequest(flow, "DEMO-SP-CA", LOA_HIGH)
    }

    @Step("Create Natural Person authentication request")
    static String getAuthnRequest(Flow flow, String providerName, String loa = LOA_HIGH, AuthnContextComparisonTypeEnumeration comparison = AuthnContextComparisonTypeEnumeration.MINIMUM, String nameIdFormat = NameIDType.UNSPECIFIED, String spType = "public") {

        AuthnRequest request = new RequestBuilderUtils().buildAuthnRequestParams(flow.connector.signatureCredential,
                providerName,
                "${flow.specificProxyService.protocol}://${flow.specificProxyService.host}:${flow.specificProxyService.port}${flow.specificProxyService.authenticationRequestUrl}",
                "${flow.connector.protocol}://${flow.connector.host}:${flow.connector.port}${flow.connector.authenticationResponseUrl}",
                "${flow.connector.protocol}://${flow.connector.host}:${flow.connector.port}${flow.connector.metadataUrl}",
                loa, comparison,nameIdFormat, spType)
        String stringResponse = OpenSAMLUtils.getXmlString(request)
        Allure.addAttachment("Request", "application/xml", stringResponse, "xml")

        SamlSignatureUtils.validateSamlReqSignature(stringResponse)
        return new String(Base64.getEncoder().encode(stringResponse.getBytes()))
    }

    @Step("Create Natural Person authentication request without nameIdFormat attribute")
    static String getAuthnRequestWithoutNameIdFormat(Flow flow, String providerName, String loa = LOA_HIGH, AuthnContextComparisonTypeEnumeration comparison = AuthnContextComparisonTypeEnumeration.MINIMUM, String spType = "public") {

        AuthnRequest request = new RequestBuilderUtils().buildAuthnRequestParams(flow.connector.signatureCredential,
                providerName,
                "${flow.specificProxyService.protocol}://${flow.specificProxyService.host}:${flow.specificProxyService.port}${flow.specificProxyService.authenticationRequestUrl}",
                "${flow.connector.protocol}://${flow.connector.host}:${flow.connector.port}${flow.connector.authenticationResponseUrl}",
                "${flow.connector.protocol}://${flow.connector.host}:${flow.connector.port}${flow.connector.metadataUrl}",
                loa, comparison, null, spType)
        String stringResponse = OpenSAMLUtils.getXmlString(request)
        Allure.addAttachment("Request", "application/xml", stringResponse, "xml")

        SamlSignatureUtils.validateSamlReqSignature(stringResponse)
        return new String(Base64.getEncoder().encode(stringResponse.getBytes()))
    }

    @Step("Create Natural Person authentication request with optional attributes")
    static String getAuthnRequestWithOptionalAttributes(Flow flow, String providerName, String loa = LOA_HIGH, AuthnContextComparisonTypeEnumeration comparison = AuthnContextComparisonTypeEnumeration.MINIMUM, String nameIdFormat = NameIDType.UNSPECIFIED, String spType = "public") {

        AuthnRequest request = new RequestBuilderUtils().buildAuthnRequestWithOptionalAttributes(flow.connector.signatureCredential,
                providerName,
                "${flow.specificProxyService.protocol}://${flow.specificProxyService.host}:${flow.specificProxyService.port}${flow.specificProxyService.authenticationRequestUrl}",
                "${flow.connector.protocol}://${flow.connector.host}:${flow.connector.port}${flow.connector.authenticationResponseUrl}",
                "${flow.connector.protocol}://${flow.connector.host}:${flow.connector.port}${flow.connector.metadataUrl}",
                loa, comparison,nameIdFormat, spType)
        String stringResponse = OpenSAMLUtils.getXmlString(request)
        Allure.addAttachment("Request", "application/xml", stringResponse, "xml")

        SamlSignatureUtils.validateSamlReqSignature(stringResponse)
        return new String(Base64.getEncoder().encode(stringResponse.getBytes()))
    }

    @Step("Create Legal Person authentication request")
    static String getLegalPersonAuthnRequest(Flow flow, String providerName, String loa = LOA_HIGH) {

        AuthnRequest request = new RequestBuilderUtils().buildLegalAuthnRequest(flow.connector.signatureCredential,
                providerName,
                "${flow.specificProxyService.protocol}://${flow.specificProxyService.host}:${flow.specificProxyService.port}${flow.specificProxyService.authenticationRequestUrl}",
                "${flow.connector.protocol}://${flow.connector.host}:${flow.connector.port}${flow.connector.authenticationResponseUrl}",
                "${flow.connector.protocol}://${flow.connector.host}:${flow.connector.port}${flow.connector.metadataUrl}",
                loa)
        String stringResponse = OpenSAMLUtils.getXmlString(request)
        Allure.addAttachment("Request", "application/xml", stringResponse, "xml")

        SamlSignatureUtils.validateSamlReqSignature(stringResponse)
        return new String(Base64.getEncoder().encode(stringResponse.getBytes()))
    }

    @Step("Start authentication process and follow redirects to TARA")
    static Response startAuthProcessFollowRedirectsToTara(Flow flow, String samlRequest) {
        Response response1 = Requests.getAuthenticationPage(flow, samlRequest)

        String action = response1.body().htmlPath().get("**.find {it.@id == 'redirectForm'}.@action")
        String token = response1.body().htmlPath().get("**.find {it.@id == 'redirectForm'}.input[0].@value")

        Response response2 = Requests.proxyServiceRequest(flow, action, token)
        response2.then().statusCode(302)

        String taraUrl =  response2.then().extract().response().getHeader("location")

        Response authenticationResponse = Requests.followRedirect(flow, taraUrl)
        String location = authenticationResponse.then().extract().response()
                .getHeader("location")
        flow.specificProxyService.setTaraLoginPageUrl(location)
        return Requests.followRedirect(flow, location)
    }

    @Step("Authenticate with MID and follow redirects to consent")
    static Response authenticateWithMidAndFollowRedirects(Flow flow, Response taraLoginPageResponse) {
        Response response = MobileId.authenticateWithMobileId(flow, taraLoginPageResponse, "00000766", "60001019906", 7000)
        return Steps.followRedirect(flow, response)
    }

    @Step("User consents with authentication")
    static Response userConsentAndFollowRedirects(Flow flow, Response response) {
        //TODO: if consent is disabled
        //String consentAction = response4.body().htmlPath().get("**.find {it.@id == 'consentSelector'}.@action")
        String consentToken = response.body().htmlPath().get("**.find {it.@id == 'consentSelector'}.input[0].@value")

        Response response1 = Requests.consentSubmit(flow, consentToken)

        return Steps.followRedirect(flow, response1)
    }

    @Step("User do not consent with authentication")
    static Response userDenyConsentAndFollowRedirects(Flow flow, Response response) {
        //TODO: if consent is disabled
        //String consentAction = response4.body().htmlPath().get("**.find {it.@id == 'consentSelector'}.@action")
        String consentToken = response.body().htmlPath().get("**.find {it.@id == 'consentSelector'}.input[0].@value")
        Response response1 = Requests.consentCancel(flow, consentToken)

        return Steps.followRedirect(flow, response1)
    }

    @Step("User cancels authentication")
    static Response userCancelAndFollowRedirects(Flow flow, Response response) {
        String returnUrl = response.body().htmlPath().get("**.find {it.@class == 'link-back-mobile'}.a.@href")
        Response cancelResponse = Requests.backToServiceProvider(flow, returnUrl)
        String backToSpUrl = cancelResponse.then().extract().response().getHeader("location")
        return Requests.followRedirect(flow, backToSpUrl)
    }

    @Step("Follow redirect")
    static Response followRedirect(Flow flow, Response response) {
        String location = response.then().extract().response().getHeader("location")

        return Requests.followRedirect(flow, location)
    }
}
