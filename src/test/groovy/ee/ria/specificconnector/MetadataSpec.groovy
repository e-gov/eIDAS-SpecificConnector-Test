package ee.ria.specificconnector

import io.qameta.allure.Feature
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


class MetadataSpec extends EEConnectorSpecification {
    Flow flow = new Flow(props)

    @Unroll
    @Feature("SP_METADATA_SIGNING")
    def "Metadata has valid signature"() {
        expect:
        MetadataUtils.validateMetadataSignature(Requests.getMetadataBody(flow))
    }

    @Unroll
    @Feature("SP_METADATA_RESPONSE")
    def "Metadata XML schema validation"() {
        expect:
        ValidatableResponse validatableResponse = Requests.getMetadataResponse(flow)
        validatableResponse.assertThat().body(XmlXsdMatcher.matchesXsd(new File("src/test/resources/saml-schema-metadata-2.0.xsd")))
    }

    @Unroll
    @Feature("SP_METADATA_VALID_UNTIL")
    def "Metadata xml check"() {
        expect:
        String metadataXml = Requests.getMetadataBody(flow)
        XmlPath xmlPath = new XmlPath(metadataXml)

        String validUntil = xmlPath.getString("EntityDescriptor.@validUntil")
        def timestamp = ZonedDateTime.parse(validUntil, DateTimeFormatter.ISO_DATE_TIME)
        def tomorrow = ZonedDateTime.now(ZoneId.of("UTC")).plusDays(1L)
        def duration = timestamp >> tomorrow
        assertTrue(Math.abs(duration.seconds) < 15)

        String foreignCountry = xmlPath.getString("EntityDescriptor.Extensions.SupportedMemberStates.MemberState")
        assertThat(foreignCountry, Matchers.equalTo("CA"))
    }

    @Unroll
    @Feature("SP_METADATA_CONTACT_INFO")
    @Feature("SP_METADATA_EXTENSIONS_SPTYPE")
    def "Metadata contact info validation"() {
        expect:
        String metadataXml = Requests.getMetadataBody(flow)
        XmlPath xmlPath = new XmlPath(metadataXml)
        String spType = xmlPath.get("EntityDescriptor.Extensions.SPType")
        String organization = xmlPath.get("EntityDescriptor.Organization")
        String support = xmlPath.get("**.find {it.@contactType == 'support'}")
        String technical = xmlPath.get("**.find {it.@contactType == 'technical'}")

        assertThat(spType, Matchers.equalTo("public"))
        assertThat(organization, Matchers.equalTo("Estonian Information System AuthorityRIAhttps://www.ria.ee"))
        assertThat(support, Matchers.equalTo("RIADeskHelphelp@ria.ee+372 663 0230"))
        assertThat(technical, Matchers.equalTo("RIADeskHelphelp@ria.ee+372 663 0230"))
    }
}