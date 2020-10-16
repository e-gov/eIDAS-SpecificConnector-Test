package ee.ria.specificconnector;

import net.shibboleth.utilities.java.support.security.RandomIdentifierGenerationStrategy;
import net.shibboleth.utilities.java.support.xml.SerializeSupport;
import net.shibboleth.utilities.java.support.xml.XMLParserException;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.XMLObjectBuilderFactory;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;

import javax.xml.namespace.QName;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;

public class OpenSAMLUtils {
    private static final Logger LOGGER = LoggerFactory.getLogger(OpenSAMLUtils.class);

    private static final RandomIdentifierGenerationStrategy secureRandomIdGenerator = new RandomIdentifierGenerationStrategy();

    public static <T> T buildSAMLObject(final Class<T> clazz) {
        T object;
        try {
            XMLObjectBuilderFactory builderFactory = XMLObjectProviderRegistrySupport.getBuilderFactory();
            QName defaultElementName = (QName)clazz.getDeclaredField("DEFAULT_ELEMENT_NAME").get(null);
            object = (T) builderFactory.getBuilder(defaultElementName).buildObject(defaultElementName);
        } catch (IllegalAccessException | NoSuchFieldException e) {
            throw new RuntimeException("SAML1 error:" + e.getMessage(), e);
        }

        return object;
    }

    public static String generateSecureRandomId() {
        return secureRandomIdGenerator.generateIdentifier();
    }

    public static String getXmlString(final XMLObject object) {
        try {
            Element entityDescriptorElement = XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(object).marshall(object);
            return SerializeSupport.nodeToString(entityDescriptorElement);
        } catch (MarshallingException e) {
            throw new RuntimeException("SAML2 error:" + e.getMessage(), e);
        }
    }

    public static org.opensaml.saml.saml2.core.Response getSamlResponse(String samlResponse) throws XMLParserException, UnmarshallingException {
        return (org.opensaml.saml.saml2.core.Response) XMLObjectSupport.unmarshallFromInputStream(
                OpenSAMLConfiguration.getParserPool(), new ByteArrayInputStream(samlResponse.getBytes(StandardCharsets.UTF_8)));
    }
}
