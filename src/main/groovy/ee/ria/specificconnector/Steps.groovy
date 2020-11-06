package ee.ria.specificconnector

import io.qameta.allure.Allure
import io.qameta.allure.Step
import io.restassured.response.Response
import org.opensaml.saml.saml2.core.AuthnContextComparisonTypeEnumeration
import org.opensaml.saml.saml2.core.AuthnRequest
import org.opensaml.saml.saml2.core.NameIDType

class Steps {
    static String LOA_HIGH = "http://eidas.europa.eu/LoA/high"
    static String LOA_LOW = "http://eidas.europa.eu/LoA/low"
    static String LOA_SUBSTANTIAL = "http://eidas.europa.eu/LoA/substantial"

    @Step("Create Natural Person authentication request")
    static String getAuthnRequest(Flow flow, String providerName, String loa = LOA_HIGH, AuthnContextComparisonTypeEnumeration comparison = AuthnContextComparisonTypeEnumeration.MINIMUM, String nameIdFormat = NameIDType.UNSPECIFIED, String spType = "public") {

        AuthnRequest request = new RequestBuilderUtils().buildAuthnRequestParams(flow.domesticSpService.signatureCredential,
                providerName,
                "${flow.domesticConnector.protocol}://${flow.domesticConnector.host}:${flow.domesticConnector.port}${flow.domesticConnector.authenticationRequestUrl}",
                "${flow.domesticSpService.protocol}://${flow.domesticSpService.host}:${flow.domesticSpService.port}${flow.domesticSpService.returnUrl}",
                "${flow.domesticSpService.protocol}://${flow.domesticSpService.host}:${flow.domesticSpService.port}${flow.domesticSpService.metadataUrl}",
                loa, comparison, nameIdFormat, spType)
        String stringResponse = OpenSAMLUtils.getXmlString(request)
        Allure.addAttachment("Request", "application/xml", stringResponse, "xml")

        SamlSignatureUtils.validateSamlReqSignature(stringResponse)
        return new String(Base64.getEncoder().encode(stringResponse.getBytes()))
    }

    @Step("Follow redirect")
    static Response followRedirect(Flow flow, Response response) {
        String location = response.then().extract().response().getHeader("location")

        return Requests.followRedirect(flow, location)
    }
}
