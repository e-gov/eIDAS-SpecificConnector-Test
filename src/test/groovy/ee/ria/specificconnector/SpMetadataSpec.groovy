package ee.ria.specificconnector

import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.internal.matcher.xml.XmlXsdMatcher
import io.restassured.path.xml.XmlPath
import io.restassured.response.ValidatableResponse
import spock.lang.Unroll

import java.security.cert.X509Certificate;
import org.opensaml.security.x509.X509Support;
import java.time.ZoneId
import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter

import static org.junit.Assert.assertEquals
import static org.junit.Assert.assertTrue




class SpMetadataSpec extends EEConnectorSpecification {
    Flow flow = new Flow(props)

    def setup() {
        flow.domesticSpService.spMetadataSigningCertificate = spMetadataSigningCertificate
        flow.domesticSpService.spSigningCertificate = spSigningCertificate
        flow.domesticSpService.encryptionCertificate = encryptionCertificate
        flow.cookieFilter = new CookieFilter()
    }

    @Unroll
    @Feature("SP_METADATA_SIGNATURE")
    @Feature("SP_METADATA_RETRIEVAL")
    def "Service provider metadata has valid signature"() {
        expect:
        String spMetadataXml = Requests.getSPMetadataBody(flow)
        MetadataUtils.validateMetadataSignature(spMetadataXml)
        MetadataUtils.validateSignature(spMetadataXml, spMetadataSigningCertificate)
    }

    @Unroll
    @Feature("SP_METADATA_RETRIEVAL")
    def "Service provider metadata has valid attributes"() {
        expect:
        String spMetadataXml = Requests.getSPMetadataBody(flow)
        XmlPath xmlPath = new XmlPath(spMetadataXml)
        String entityID = xmlPath.getString("EntityDescriptor.@entityID")
        assertEquals("Correct entityID is returned", flow.domesticSpService.fullMetadataUrl.toString(), entityID)
        String validUntil = xmlPath.getString("EntityDescriptor.@validUntil")
        def timestamp = ZonedDateTime.parse(validUntil, DateTimeFormatter.ISO_DATE_TIME)
        def now = ZonedDateTime.now(ZoneId.of("UTC")).plusYears(1L)
        def duration = timestamp >> now
        assertTrue(Math.abs(duration.seconds) < 15)

        String nameIdFormat = xmlPath.getString("EntityDescriptor.SPSSODescriptor.NameIDFormat")
        assertEquals("Correct NameIDFormat is returned", "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified", nameIdFormat)
        String binding = xmlPath.getString("EntityDescriptor.SPSSODescriptor.AssertionConsumerService.@Binding")
        assertEquals("Correct Binding is returned", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", binding)
        String locationUrl = xmlPath.getString("EntityDescriptor.SPSSODescriptor.AssertionConsumerService.@Location")
        assertEquals("Correct Location is returned", flow.domesticSpService.fullReturnUrl.toString(), locationUrl)

        String encryptionCertificate = xmlPath.getString("EntityDescriptor.SPSSODescriptor.KeyDescriptor[1].KeyInfo.X509Data.X509Certificate")
        X509Certificate x509Encryption = X509Support.decodeCertificate(encryptionCertificate)
        assertEquals("Correct encryption certificate", x509Encryption, flow.domesticSpService.encryptionCertificate)
        String signingCertificate = xmlPath.getString("EntityDescriptor.SPSSODescriptor.KeyDescriptor[0].KeyInfo.X509Data.X509Certificate")
        X509Certificate x509Signing = X509Support.decodeCertificate(signingCertificate)
        assertEquals("Correct signing certificate", x509Signing, flow.domesticSpService.spSigningCertificate)
    }

    @Unroll
    @Feature("SP_METADATA_RETRIEVAL")
    def "Metadata XML schema validation"() {
        expect:
        ValidatableResponse validatableResponse = Requests.getSPMetadataResponse(flow)
        validatableResponse.assertThat().body(XmlXsdMatcher.matchesXsd(new File("src/test/resources/saml-schema-metadata-2.0.xsd")))
    }

}