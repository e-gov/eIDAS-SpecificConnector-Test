package ee.ria.specificconnector

import io.qameta.allure.Feature
import io.restassured.filter.cookie.CookieFilter
import io.restassured.internal.matcher.xml.XmlXsdMatcher
import io.restassured.path.xml.XmlPath

import io.restassured.response.ValidatableResponse
import org.hamcrest.Matchers
import java.time.ZoneId
import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter

import static org.junit.Assert.assertThat
import spock.lang.Unroll

import static org.junit.Assert.assertTrue


class SpMetadataSpec extends EEConnectorSpecification {
    Flow flow = new Flow(props)

    def setup() {
        flow.domesticConnector.spRequestSigningCertificate = spRequestSigningCertificate
        flow.cookieFilter = new CookieFilter()
    }

    @Unroll
    @Feature("SP_METADATA_SIGNATURE")
    def "Service provider metadata has valid signature"() {
        expect:
        String spMetadataXml = Requests.getSPMetadataBody(flow)
        MetadataUtils.validateMetadataSignature(spMetadataXml)
        MetadataUtils.validateSignature(spMetadataXml, spRequestSigningCertificate)
    }

}