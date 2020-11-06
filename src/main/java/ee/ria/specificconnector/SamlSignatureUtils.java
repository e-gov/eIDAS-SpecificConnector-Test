package ee.ria.specificconnector;

import io.restassured.path.xml.XmlPath;
import org.opensaml.saml.common.SignableSAMLObject;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.EncryptedAssertion;
import org.opensaml.saml.saml2.encryption.Decrypter;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.CredentialSupport;
import org.opensaml.security.x509.X509Credential;
import org.opensaml.security.x509.X509Support;
import org.opensaml.xmlsec.encryption.support.DecryptionException;
import org.opensaml.xmlsec.encryption.support.InlineEncryptedKeyResolver;
import org.opensaml.xmlsec.keyinfo.impl.StaticKeyInfoCredentialResolver;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.SignatureValidator;

import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;

public class SamlSignatureUtils {

    protected static void validateSignature(String body, java.security.cert.X509Certificate x509) {
        try {
            x509.checkValidity();
            SignableSAMLObject signableObj = XmlUtils.unmarshallElement(body);
            X509Credential credential = CredentialSupport.getSimpleCredential(x509, null);
            SignatureValidator.validate(signableObj.getSignature(), credential);
        } catch (SignatureException e) {
            throw new RuntimeException("Signature validation in validateSignature() failed: " + e.getMessage(), e);
        } catch (CertificateNotYetValidException e) {
            //Expired certificates are used in test environment
            return;
        } catch (CertificateExpiredException e) {
            //Expired certificates are used in test environment
            return;
        }
    }

    public static Assertion decryptAssertion(EncryptedAssertion encryptedAssertion, Credential credential) {
        StaticKeyInfoCredentialResolver keyInfoCredentialResolver = new StaticKeyInfoCredentialResolver(credential);

        Decrypter decrypter = new Decrypter(null, keyInfoCredentialResolver, new InlineEncryptedKeyResolver());
        decrypter.setRootInNewDocument(true);

        try {
            return decrypter.decrypt(encryptedAssertion);
        } catch (DecryptionException e) {
            throw new RuntimeException("Error decrypting assertion", e);
        }
    }

    public static void validateSamlReqSignature(String body) {
        XmlPath metadataXml = new XmlPath(body);
        try {
            java.security.cert.X509Certificate x509 = X509Support.decodeCertificate(metadataXml.getString("AuthnRequest.Signature.KeyInfo.X509Data.X509Certificate"));
            validateSignature(body, x509);
        } catch (CertificateException e) {
            throw new RuntimeException("Certificate parsing in validateSignature() failed:" + e.getMessage(), e);
        }
    }
}
