package ee.ria.specificconnector.tara

import ee.ria.specificconnector.Flow
import io.qameta.allure.Step
import io.qameta.allure.restassured.AllureRestAssured
import io.restassured.response.Response

import static io.restassured.RestAssured.given

class Oidc {
    @Step("{flow.endUser}Follow redirects after authorization")
    static Response followLoginRedirects(Flow flow, String url) {
        Response oauth2Response = oauth2AuthorizeRedirect(flow, url)
        return oidcAuthorizeRedirect(flow, oauth2Response.getHeader("location"))
    }
    @Step("{flow.endUser}Follow redirect - /oauth2.0/callbackAuthorize")
    static Response oauth2AuthorizeRedirect(Flow flow, String location) {
        return given()
                .filter(flow.getCookieFilter())
                .filter(new AllureRestAssured())
                .relaxedHTTPSValidation()
                .redirects().follow(false)
                .when()
                .urlEncodingEnabled(false)
                .get(location).then()
                .extract().response()
    }

    @Step("{flow.endUser}Follow redirect - /oidc/authorize")
    static Response oidcAuthorizeRedirect(Flow flow, String location) {
        return given()
                .filter(flow.getCookieFilter())
                .filter(new AllureRestAssured())
                .relaxedHTTPSValidation()
                .redirects().follow(false)
                .when()
                .urlEncodingEnabled(false)
                .get(location)
                .then()
                .extract().response()
    }
}
