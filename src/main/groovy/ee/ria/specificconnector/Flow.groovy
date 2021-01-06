package ee.ria.specificconnector

import groovy.transform.Canonical
import io.restassured.filter.cookie.CookieFilter
import org.opensaml.security.credential.Credential
import java.security.cert.X509Certificate

@Canonical
class Flow {
    Properties properties
    ForeignProxyService foreignProxyService
    DomesticSpService domesticSpService
    DomesticConnector domesticConnector
    ForeignIdpProvider foreignIdpProvider
    CookieFilter cookieFilter
    String token
    String nextEndpoint
    String requestMessage
    String relayState

    Flow(Properties properties) {
        this.properties = properties
        this.foreignProxyService = new ForeignProxyService(properties)
        this.domesticConnector = new DomesticConnector(properties)
        this.domesticSpService = new DomesticSpService(properties)
        this.foreignIdpProvider = new ForeignIdpProvider(properties)
        this.token = ""
        this.nextEndpoint = ""
        this.requestMessage = ""
        this.relayState = ""
    }
}

@Canonical
class ForeignProxyService {
    String host
    String port
    String protocol
    String callbackUrl
    String authenticationRequestUrl
    String consentUrl
    String heartbeatUrl

    @Lazy fullCallbackUrl = "${protocol}://${host}:${port}${callbackUrl}"
    @Lazy fullConsentUrl = "${protocol}://${host}:${port}${consentUrl}"

    ForeignProxyService(Properties properties) {
        this.host = properties."ca-proxyservice.host"
        this.port = properties."ca-proxyservice.port"
        this.protocol = properties."ca-proxyservice.protocol"
        this.callbackUrl = properties."ca-proxyservice.callbackUrl"
        this.authenticationRequestUrl = properties."ca-proxyservice.authenticationRequestUrl"
        this.consentUrl = properties."ca-proxyservice.consentUrl"
        this.heartbeatUrl = properties."ca-proxyservice.heartbeatUrl"
    }
}

@Canonical
class DomesticConnector {
    String host
    String port
    String protocol
    String metadataUrl
    String heartbeatUrl
    String eidasResponseUrl
    String authenticationRequestUrl
    String eidasColleagueResponseUrl
    X509Certificate connectorSigningCertificate

    @Lazy fullMetadataUrl = "${protocol}://${host}:${port}${metadataUrl}"
    @Lazy metadataUrlWithoutPort = "${protocol}://${host}${metadataUrl}"
    @Lazy fullAuthenticationRequestUrl = "${protocol}://${host}:${port}${authenticationRequestUrl}"
    @Lazy fullAuthenticationRequestUrlWithoutPort = "${protocol}://${host}${authenticationRequestUrl}"
    @Lazy fullheartbeatUrl = "${protocol}://${host}:${port}${heartbeatUrl}"
    @Lazy fullEidasResponseUrl = "${protocol}://${host}:${port}${eidasResponseUrl}"
    @Lazy fullEidasColleagueResponseUrl = "${protocol}://${host}:${port}${eidasColleagueResponseUrl}"

    DomesticConnector(Properties properties) {
        this.host = properties."ee-connector.host"
        this.port = properties."ee-connector.port"
        this.protocol = properties."ee-connector.protocol"
        this.metadataUrl = properties."ee-connector.metadataUrl"
        this.authenticationRequestUrl = properties."ee-connector.authenticationRequestUrl"
        this.heartbeatUrl = properties."ee-connector.heartbeatUrl"
        this.eidasResponseUrl = properties."ee-connector.eidasResponseUrl"
        this.eidasColleagueResponseUrl = properties."ee-connector.eidasColleagueResponseUrl"
    }
}

@Canonical
class DomesticSpService {
    String providerName
    String host
    String port
    String protocol
    String returnUrl
    String metadataUrl
    Credential signatureCredential
    Credential encryptionCredential
    Credential metadataCredential
    Credential expiredCredential
    Credential unsupportedCredential
    Credential unsupportedByConfigurationCredential
    String samlRequestId
    X509Certificate encryptionCertificate
    X509Certificate spMetadataSigningCertificate
    X509Certificate spSigningCertificate

    @Lazy fullMetadataUrl = "${protocol}://${host}:${port}${metadataUrl}"
    @Lazy fullReturnUrl = "${protocol}://${host}:${port}${returnUrl}"

    DomesticSpService(Properties properties) {
        this.providerName = properties."ee-spservice.providerName"
        this.host = properties."ee-spservice.host"
        this.port = properties."ee-spservice.port"
        this.protocol = properties."ee-spservice.protocol"
        this.returnUrl = properties."ee-spservice.returnUrl"
        this.metadataUrl = properties."ee-spservice.metadataUrl"
    }
}

@Canonical
class ForeignIdpProvider {
    String host
    String port
    String protocol
    String responseUrl

    @Lazy fullResponseUrl = "${protocol}://${host}:${port}${responseUrl}"
    ForeignIdpProvider(Properties properties) {
        this.host = properties."idp.host"
        this.port = properties."idp.port"
        this.protocol = properties."idp.protocol"
        this.responseUrl = properties."idp.responseUrl"
    }
}