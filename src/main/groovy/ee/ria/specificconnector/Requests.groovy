package ee.ria.specificconnector

import io.qameta.allure.Step
import io.qameta.allure.restassured.AllureRestAssured
import io.restassured.RestAssured
import io.restassured.response.Response
import io.restassured.response.ValidatableResponse

import static io.restassured.RestAssured.config
import static io.restassured.RestAssured.given
import static io.restassured.config.EncoderConfig.encoderConfig

class Requests {
    @Step("Get metadata body")
    static String getMetadataBody(Flow flow) {
        return given()
                .config(config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8")))
                .relaxedHTTPSValidation()
                .filter(new AllureRestAssured())
                .when()
                .get(flow.domesticConnector.fullMetadataUrl)
                .then()
                .statusCode(200)
                .extract().body().asString()
    }

    @Step("Get node metadata body")
    static String getEidasNodeMetadataBody(Flow flow) {
        return given()
                .config(config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8")))
                .relaxedHTTPSValidation()
                .filter(new AllureRestAssured())
                .when()
                .get(flow.domesticConnector.fullEidasNodeMetadataUrl)
                .then()
                .statusCode(200)
                .extract().body().asString()
    }

    @Step("Get domestic connector metadata response")
    static ValidatableResponse getMetadataResponse(Flow flow) {
        return given()
                .config(config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8")))
                .relaxedHTTPSValidation()
                .filter(new AllureRestAssured())
                .when()
                .get(flow.domesticConnector.fullMetadataUrl)
                .then()
                .statusCode(200)
    }

    @Step("Get domestic service provider metadata body")
    static String getSPMetadataBody(Flow flow) {
        return given()
                .config(config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8")))
                .relaxedHTTPSValidation()
                .filter(new AllureRestAssured())
                .when()
                .get(flow.domesticSpService.fullMetadataUrl)
                .then()
                .statusCode(200)
                .extract().body().asString()
    }

    @Step("Get domestic service provider metadata response")
    static ValidatableResponse getSPMetadataResponse(Flow flow) {
        return given()
                .config(config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8")))
                .relaxedHTTPSValidation()
                .filter(new AllureRestAssured())
                .when()
                .get(flow.domesticSpService.fullMetadataUrl)
                .then()
                .statusCode(200)
    }

    @Step("Get heartbeat")
    static Response getHeartbeat(Flow flow) {
        return given()
                .config(config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8")))
                .relaxedHTTPSValidation()
                .filter(new AllureRestAssured())
                .when()
                .get(flow.domesticConnector.fullheartbeatUrl)
                .then()
                .statusCode(200)
                .extract().response()
    }

    @Step("Open authentication page")
    static Response startAuthentication(Flow flow, String requestType, String samlRequest, String additionalParam = "salt", String additionalParamValue = "lqx") {
        Response response =
                given()
                        .filter(flow.cookieFilter)
                        .filter(new AllureRestAssured())
                        .param("SAMLRequest", samlRequest)
                        .param(additionalParam, additionalParamValue)
                        .param("country", "CA")
                        .config(config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8"))).relaxedHTTPSValidation()
                        .when()
                        .redirects().follow(false)
                        .request(requestType, flow.domesticConnector.fullAuthenticationRequestUrl)
                        .then()
                        .extract().response()
        return response
    }

    @Step("Open authentication page with duplicate params")
    static Response startAuthenticationWithDuplicateParams(Flow flow, String requestType, String samlRequest, String additionalParam = "salt", String additionalParamValue = "lqx") {
        Response response =
                given()
                        .filter(flow.cookieFilter)
                        .filter(new AllureRestAssured())
                        .param("SAMLRequest", samlRequest)
                        .param("RelayState")
                        .param(additionalParam, additionalParamValue)
                        .param("country", "CA")
                        .config(config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8"))).relaxedHTTPSValidation()
                        .when()
                        .request(requestType, flow.domesticConnector.fullAuthenticationRequestUrl)
                        .then()
                        .extract().response()
        return response
    }

    @Step("Open authentication page with parameters")
    static Response startAuthenticationWithParameters(Flow flow, String requestType, Map hashMap) {
        Response response =
                given()
                        .filter(flow.cookieFilter)
                        .filter(new AllureRestAssured())
                        .params(hashMap)
                        .config(config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8"))).relaxedHTTPSValidation()
                        .when()
                        .request(requestType, flow.domesticConnector.fullAuthenticationRequestUrl)
                        .then()
                        .extract().response()
        return response
    }

    @Step("Proxy Service Request")
    static Response proxyServiceRequest(Flow flow, String requestType, String actionUrl, String token) {
        Response response =
                given()
                        .filter(flow.cookieFilter)
                        .filter(new AllureRestAssured())
                        .param("token", token)
                        .config(config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8"))).relaxedHTTPSValidation()
                        .when()
                        .request(requestType, actionUrl)
                        .then()
                        .extract().response()
        return response
    }

    @Step("Follow redirect")
    static Response followRedirect(Flow flow, String location) {
        return given()
                .filter(flow.cookieFilter)
                .filter(new AllureRestAssured())
                .relaxedHTTPSValidation()
                .when()
                .redirects().follow(false)
                .urlEncodingEnabled(false)
                .get(location)
                .then()
                .extract().response()
    }

    @Step("Colleague Request")
    static Response colleagueRequest(Flow flow, String requestType, String samlRequest, String url) {
        Response response =
                given()
                        .filter(flow.cookieFilter)
                        .filter(new AllureRestAssured())
                        .param("SAMLRequest", samlRequest)
                        .config(config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8"))).relaxedHTTPSValidation()
                        .when()
                        .request(requestType, url)
                        .then()
                        .extract().response()
        return response
    }

    @Step("IdP request")
    static Response idpRequest(Flow flow, String requestType, String actionUrl, String smsspRequest) {
        Response response =
                given()
                        .filter(flow.cookieFilter)
                        .filter(new AllureRestAssured())
                        .param("SMSSPRequest", smsspRequest)
                        .config(config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8"))).relaxedHTTPSValidation()
                        .when()
                        .request(requestType, actionUrl)
                        .then()
                        .extract().response()
        return response
    }

    @Step("IdP authorization")
    static Response idpAuthorizationRequest(Flow flow, String smsspToken, String smsspTokenRequestJson, String idpUsername, String idpPassword, String eidasloa) {
        Response response =
                given()
                        .filter(flow.cookieFilter)
                        .filter(new AllureRestAssured())
                        .formParam("smsspToken", smsspToken)
                        .formParam("username", idpUsername)
                        .formParam("password", idpPassword)
                        .formParam("eidasloa", eidasloa)
                        .formParam("eidasnameid", "persistent")
                        .formParam("callback", flow.foreignProxyService.fullCallbackUrl)
                        .formParam("jSonRequestDecoded", smsspTokenRequestJson)
                        .formParam("doNotmodifyTheResponse", "off")
                        .config(config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8"))).relaxedHTTPSValidation()
                        .when()
                        .post(flow.foreignIdpProvider.fullResponseUrl)
                        .then()
                        .extract().response()
        return response
    }

    @Step("IdP authorization response")
    static Response idpAuthorizationResponse(Flow flow, String action, String smsspTokenResponseJson) {
        Response response =
                given()
                        .filter(flow.cookieFilter)
                        .filter(new AllureRestAssured())
                        .formParam("SMSSPResponse", smsspTokenResponseJson)

                        .config(config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8"))).relaxedHTTPSValidation()
                        .when()
                        .post(action)
                        .then()
                        .extract().response()
        return response
    }

    @Step("After Citizen Consent response")
    static Response afterCitizenConsentResponse(Flow flow, String binaryLightToken) {
        Response response =
                given()
                        .filter(flow.cookieFilter)
                        .filter(new AllureRestAssured())
                        .formParam("binaryLightToken", binaryLightToken)
                        .config(config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8"))).relaxedHTTPSValidation()
                        .when()
                        .post(flow.foreignProxyService.fullConsentUrl)
                        .then()
                        .extract().response()
        return response
    }

    @Step("Deny Consent response")
    static Response denyConsentResponse(Flow flow, String binaryLightToken) {
        Response response =
                given()
                        .filter(flow.cookieFilter)
                        .filter(new AllureRestAssured())
                        .formParam("binaryLightToken", binaryLightToken)
                        .formParam("cancel", "true")
                        .config(config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8"))).relaxedHTTPSValidation()
                        .when()
                        .post(flow.foreignProxyService.fullConsentUrl)
                        .then()
                        .extract().response()
        return response
    }

    @Step("Eidas authorization response")
    static Response getAuthorizationResponseFromEidas(Flow flow, String requestType, String actionUrl, String lightToken) {
        Response response =
                given()
                        .filter(flow.cookieFilter)
                        .filter(new AllureRestAssured())
                        .param("token", lightToken)
                        .config(config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8"))).relaxedHTTPSValidation()
                        .when()
                        .redirects().follow(false)
                        .request(requestType, actionUrl)
                        .then()
                        .extract().response()
        return response
    }

    @Step("Eidas authorization response with additional parameters")
    static Response getAuthorizationResponseFromEidasWithSomeUnusedParams(Flow flow, String requestType, String actionUrl, String lightToken, String paramName) {
        Response response =
                given()
                        .filter(flow.cookieFilter)
                        .filter(new AllureRestAssured())
                        .param("token", lightToken)
                        .param(paramName, "c3BlY2lmaWNDb21tdW5pY2F0aW9uRGVmaW5pdGlvbkNvbm5lY3RvclJlc3BvbnNlfGM4NGE4NGUyLWRhNmQtNGFkMi1hNGIwLWEwNWMzMDA2MTJiYnwyMDIwLTExLTA1IDAwOjIwOjM3IDcwOXxKdGtoVFlJYXZjMy9sU3ZjZm8yM2xSOGxabUpzQ2xELzlwQVZQYzJ2c1FnPQ==")
                        .config(config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8"))).relaxedHTTPSValidation()
                        .when()
                        .redirects().follow(false)
                        .request(requestType, actionUrl)
                        .then()
                        .extract().response()
        return response
    }

    @Step("Eidas Colleague Response")
    static Response colleagueResponse(Flow flow, String samlResponse) {
        Response response =
                given()
                        .filter(flow.cookieFilter)
                        .filter(new AllureRestAssured())
                        .formParam("SAMLResponse", samlResponse)
                        .config(config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8"))).relaxedHTTPSValidation()
                        .when()
                        .post(flow.domesticConnector.fullEidasColleagueResponseUrl)
                        .then()
                        .extract().response()
        return response
    }

    @Step("Send LightRequest to Eidas")
    static Response sendLightTokenRequestToEidas(Flow flow, String url, String lightToken) {
        Response response =
                given()
                        .filter(flow.cookieFilter)
                        .filter(new AllureRestAssured())
                        .formParam("token", lightToken)
                        .config(config().encoderConfig(encoderConfig().defaultContentCharset("UTF-8"))).relaxedHTTPSValidation()
                        .when()
                        .post(url)
                        .then()
                        .extract().response()
        return response
    }

}
