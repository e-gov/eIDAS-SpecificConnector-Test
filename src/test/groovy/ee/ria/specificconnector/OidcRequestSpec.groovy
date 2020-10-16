package ee.ria.specificconnector

import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.response.Response
import org.hamcrest.Matchers
import spock.lang.Unroll

import static org.junit.Assert.assertThat

class OidcRequestSpec extends SpecificConnectorSpecification {

    Flow flow = new Flow(props)

    def setup() {
        flow.connector.signatureCredential = signatureCredential
        flow.connector.encryptionCredential = encryptionCredential
        flow.cookieFilter = new CookieFilter()
    }

    @Unroll
    @Feature("IDP_START_AUTH")
    @Feature("IDP_START_AUTH_METHODS_SCOPES")
    def "Verification of correct OIDC request"() {
        expect:
        String samlRequest = Steps.getAuthnRequest(flow, "DEMO-SP-CA" , requestLoa)
        Response response1 = Requests.getAuthenticationPage(flow, samlRequest)

        String action = response1.body().htmlPath().get("**.find {it.@id == 'redirectForm'}.@action")
        String token = response1.body().htmlPath().get("**.find {it.@id == 'redirectForm'}.input[0].@value")

        Response response2 = Requests.proxyServiceRequest(flow, action, token)
        response2.then().statusCode(302)

        String taraUrl =  response2.then().extract().response().getHeader("location")

        assertThat(taraUrl, Matchers.stringContainsInOrder(mainStructure))
        assertThat(taraUrl, Matchers.stringContainsInOrder(transformedLoa))
        assertThat(taraUrl, Matchers.stringContainsInOrder(defaultLocale))

        where:
        requestLoa                               || transformedLoa           || defaultLocale     || mainStructure
        "http://eidas.europa.eu/LoA/low"         || "acr_values=low"         || "&ui_locales=et&" || "scope=openid%20idcard%20mid%20eidas:attribute:person_identifier%20eidas:attribute:family_name%20eidas:attribute:first_name%20eidas:attribute:date_of_birth&response_type=code&client_id="
        "http://eidas.europa.eu/LoA/substantial" || "acr_values=substantial" || "&ui_locales=et&" || "scope=openid%20idcard%20mid%20eidas:attribute:person_identifier%20eidas:attribute:family_name%20eidas:attribute:first_name%20eidas:attribute:date_of_birth&response_type=code&client_id="
        "http://eidas.europa.eu/LoA/high"        || "acr_values=high"        || "&ui_locales=et&" || "scope=openid%20idcard%20mid%20eidas:attribute:person_identifier%20eidas:attribute:family_name%20eidas:attribute:first_name%20eidas:attribute:date_of_birth&response_type=code&client_id="

    }

    @Unroll
    @Feature("IDP_START_AUTH_SCOPES_ATTR")
    def "request authentication with optional attributes"() {
        expect:
        String samlRequest = Steps.getAuthnRequest(flow, "DEMO-SP-CA")
        Response response1 = Requests.getAuthenticationPage(flow, samlRequest)

        String action = response1.body().htmlPath().get("**.find {it.@id == 'redirectForm'}.@action")
        String token = response1.body().htmlPath().get("**.find {it.@id == 'redirectForm'}.input[0].@value")

        Response response2 = Requests.proxyServiceRequest(flow, action, token)
        response2.then().statusCode(302)

        String taraUrl =  response2.then().extract().response().getHeader("location")

        assertThat("Only supported attributes should be requested", taraUrl, Matchers.stringContainsInOrder("scope=openid%20idcard%20mid%20eidas:attribute:person_identifier%20eidas:attribute:family_name%20eidas:attribute:first_name%20eidas:attribute:date_of_birth&"))
    }
}
