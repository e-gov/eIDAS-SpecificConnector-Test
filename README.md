<img src='img/eu_regional_development_fund_horizontal.jpg'>

# eIDAS Connector integration tests

Tests for eIDAS connector component (both eIDAS standard component and Estonia specific component)

## Prerequisites

1. SUT (eIDAS connector) must be deployed. It must have country CA configured to demo proxy service with idp (provided by the eIDAS demo package).
2. ee-spservice metadata must be available. Either by deploying mock service or other means.
3. Fetch the tests:

 `git clone https://github.com/e-gov/eIDAS-SpecificConnector-Test.git`

## Configuration of tests

1. Configure the properties file. application.properties file needs to be either in `src/test/resources` directory or its location configured with .env file in `src/test/resources` directory.
   Example of .env file content:
```
configuration_base_path=/home/me/IdeaProjects/specificconnector-configuration
configuration_path=dev-local
```   
The example application.properties file with default values is given ../src/test/resource/sample_application.properties

Description of values:

**ee-connector** - configuration parameters for the SUT (Estonian implementation of eIDAS Connector service)

**ee-spservice** - configuration parameters for tests.

**ca-proxyservice** - configuration parameters for receiving member state (CA) proxy service.

**idp** - configuration parameters for receiving member state (CA) authentication service.
 
| Parameter | Default |  Description |
|------------|--------------|------------|
| ee-connector.protocol | https  | Service protocol. | 
| ee-connector.host | eidas-specificconnector  | Service URL. |
| ee-connector.port | 8443  | Service port. |
| ee-connector.heartbeatUrl | /SpecificConnector/heartbeat | Heartbeat endoint |
| ee-connector.metadataUrl | /SpecificConnector/ConnectorResponderMetadata | Service metadata endpoint. |
| ee-connector.authenticationRequestUrl | /SpecificConnector/ServiceProvider | Endpoint for authentication start. |
| ee-connector.eidasResponseUrl | /SpecificConnector/ConnectorResponse | Endpoint for returning authentication response to specific component. |
| ee-connector.eidasColleagueResponseUrl | /EidasNode/ColleagueResponse | Endpoint for response in eIDAS node component| 
| ee-connector.truststore.file | truststore.p12 | Truststore for accepted service provider metadata signing certificates. |
| ee-connector.truststore.password | changeit | Truststore password. | 
| ee-connector.truststore.spRequestSigningKeyId | eidas-eeserviceprovider-signing | Key id used for service provider request signing.|
| ee-spservice.providerName | eidas-eeserviceprovider | Service provider name for usage in tests. Must be trusted by Connector service | 
| ee-spservice.protocol | https | Service protocol. | 
| ee-spservice.host | eidas-eeserviceprovider | Service URL. | 
| ee-spservice.port | 8889 | Service port. | 
| ee-spservice.returnUrl | /returnUrl | Return URL of service provider. | 
| ee-spservice.metadataUrl | /metadata | Service provider metadata endpoint. | 
| ee-spservice.keystore.file | saml-keystore.p12 | Keystore for signing requests. | 
| ee-spservice.keystore.password | changeit | Keystore password. | 
| ee-spservice.keystore.requestSigningKeyId | eidas-eeserviceprovider-sign | Key id for signing requests. | 
| ee-spservice.keystore.requestSigningKeyPassword | changeit | Password for signing key. | 
| ee-spservice.keystore.samlAssertionDecryptKey | eidas-eeserviceprovider-encrypt | Key if for decrypting assertion. | 
| ee-spservice.keystore.samlAssertionDecryptPassword | changeit | Password for decryption key. | 
| ee-spservice.keystore.metadataKeyId | eidas-eeserviceprovider-metadata | Metadata signing key id. | 
| ee-spservice.keystore.metadataKeyPassword | changeit | Password for metadata signing key. | 
| ee-spservice.test.keystore.file | src/test/resources/test-keystore.p12  | Keystore containing non valid keys for tests. | 
| ee-spservice.test.keystore.password | changeit  | Password for keystore. | 
| ee-spservice.test.keystore.expiredKeyId | eidas-expired  | Key id for expired certificate. | 
| ee-spservice.test.keystore.expiredKeyPassword | changeit  | Password for expired key. | 
| ee-spservice.test.keystore.unsupportedKeyId | eidas-unsupported-algoritm  | Key id for unsupported key. | 
| ee-spservice.test.keystore.unsupportedKeyPassword | changeit  | Password for unsupported key. | 
| ee-spservice.test.keystore.unsupportedByConfigurationKeyId | eidas-unsupported-by-configuration  | Key id for unsupported in configuration key.  | 
| ee-spservice.test.keystore.unsupportedByConfigurationKeyPassword | changeit  | Password for unsupported in configuration key. | 
| ca-proxyservice.protocol | https | Service protocol. | 
| ca-proxyservice.host | eidas-caproxy | Service URL. | 
| ca-proxyservice.port | 8080 | Service port. | 
| ca-proxyservice.authenticationRequestUrl | /EidasNode/ColleagueRequest | Endpoint for starting authentication. | 
| ca-proxyservice.callbackUrl | /SpecificProxyService/IdpResponse | Endpoint for receiving the authentication response. | 
| ca-proxyservice.consentUrl | /SpecificProxyService/AfterCitizenConsentResponse | Endpoint for receiving consent. | 
| idp.protocol | https | Service protocol. | 
| idp.host | eidas-caproxy | Service URL. | 
| idp.port | 8081 | Service port. | 
| idp.responseUrl | /IdP/Response | Endpoint for response. | 

## Execute tests and generate report

1. To run the tests execute:

`./mvnw clean test`

2. Results are present in: 

a) Surefire plugin generates reports in ../target/surefire-reports folder.

b) For a comprehensive report, Allure is required ([instructions for download.](https://docs.qameta.io/allure/#_installing_a_commandline)). To generate the report execute:

`allure serve .../eidas-connector-test/allure-results/`

##To see Allure report after running tests in IntelliJ

Configure correct Allure results directory in IntelliJ in order to view Allure report when running tests from IntelliJ
`Run-> Edit configurations-> Templates-> JUnit-> VM Options: -ea -Dallure.results.directory=$ProjectFileDir$/target/allure-results`

And delete all existing run configurations
