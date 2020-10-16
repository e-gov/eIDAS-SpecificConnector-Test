package ee.ria.specificconnector

import groovy.transform.Canonical
import io.restassured.config.RestAssuredConfig
import io.restassured.filter.cookie.CookieFilter
import org.opensaml.security.credential.Credential

@Canonical
class Flow {
    RestAssuredConfig sslConfig
    Properties properties
    SpecificProxyService specificProxyService
    Connector connector
    CookieFilter cookieFilter
    String endUser=""

    Flow(Properties properties) {
        this.properties = properties
        this.specificProxyService = new SpecificProxyService(properties)
        this.connector = new Connector(properties)
    }
}

@Canonical
class SpecificProxyService {
    String host
    String port
    String protocol
    String metadataUrl
    String authenticationRequestUrl
    String consentUrl
    String taraLoginPageUrl
    String heartbeatUrl
    // @formatter:off
    @Lazy fullMetadataUrl = "${protocol}://${host}:${port}${metadataUrl}"
    @Lazy fullAuthenticationRequestUrl = "${protocol}://${host}:${port}${authenticationRequestUrl}"
    @Lazy fullConsentUrl = "${protocol}://${host}:${port}${consentUrl}"
    @Lazy fullheartbeatUrl = "${protocol}://${host}:${port}${heartbeatUrl}"

    // @formatter:on
    SpecificProxyService(Properties properties) {
        this.host = properties."specificproxyservice.host"
        this.port = properties."specificproxyservice.port"
        this.protocol = properties."specificproxyservice.protocol"
        this.metadataUrl = properties."specificproxyservice.metadataUrl"
        this.authenticationRequestUrl = properties."specificproxyservice.authenticationRequestUrl"
        this.consentUrl=properties."specificproxyservice.consentUrl"
        this.heartbeatUrl=properties."specificproxyservice.heartbeatUrl"
    }

}

@Canonical
class Connector {
    String host
    String port
    String protocol
    String metadataUrl
    String heartbeatUrl
    String authenticationResponseUrl
    Credential signatureCredential
    Credential encryptionCredential
    // @formatter:off
    @Lazy fullMetadataUrl = "${protocol}://${host}:${port}${metadataUrl}"
    @Lazy fullAuthenticationResponseUrl = "${protocol}://${host}:${port}${authenticationResponseUrl}"
    @Lazy fullheartbeatUrl = "${protocol}://${host}:${port}${heartbeatUrl}"

    // @formatter:on
    Connector(Properties properties) {
        this.host = properties."connector.host"
        this.port = properties."connector.port"
        this.protocol = properties."connector.protocol"
        this.metadataUrl = properties."connector.metadataUrl"
        this.authenticationResponseUrl = properties."connector.authenticationResponseUrl"
        this.heartbeatUrl=properties."connector.heartbeatUrl"
    }

}
