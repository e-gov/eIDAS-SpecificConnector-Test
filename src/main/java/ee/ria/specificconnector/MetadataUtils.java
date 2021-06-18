package ee.ria.specificconnector;

import io.restassured.path.xml.XmlPath;
import org.opensaml.saml.common.SignableSAMLObject;
import org.opensaml.security.credential.CredentialSupport;
import org.opensaml.security.x509.X509Credential;
import org.opensaml.security.x509.X509Support;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.SignatureValidator;

import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;

public class MetadataUtils {

    protected static void validateMetadataSignature(String body) {
        XmlPath metadataXml = new XmlPath(body);
        try {
            java.security.cert.X509Certificate x509 = X509Support.decodeCertificate(metadataXml.getString("EntityDescriptor.Signature.KeyInfo.X509Data.X509Certificate"));
            validateSignature(body, x509);
        } catch (CertificateException e) {
            throw new RuntimeException("Certificate parsing in validateSignature() failed:" + e.getMessage(), e);
        }
    }
    protected static void validateSignature(String body, java.security.cert.X509Certificate x509) {
        try {
            x509.checkValidity();
            SignableSAMLObject signableObj = XmlUtils.unmarshallElement(body);
            X509Credential credential = CredentialSupport.getSimpleCredential(x509, null);
            SignatureValidator.validate(signableObj.getSignature(), credential);
        } catch (SignatureException e) {
            throw new RuntimeException("Signature validation in validateSignature() failed: " + e.getMessage(), e);
        } catch (CertificateNotYetValidException e) {
            throw new RuntimeException("Certificate is not yet valid: " + e.getMessage(), e);
        } catch (CertificateExpiredException e) {
            throw new RuntimeException("Certificate is expired: " + e.getMessage(), e);
        }
    }

    static java.security.cert.X509Certificate retrieveSigningCertificate(String metadataResponse) throws CertificateException {
        XmlPath metadataXml = new XmlPath(metadataResponse);
        return X509Support.decodeCertificate(metadataXml.getString("EntityDescriptor.Signature.KeyInfo.X509Data.X509Certificate"));
    }
}
