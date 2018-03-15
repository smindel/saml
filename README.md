# PHP SAML 2.0 Adapter

This library helps creating AuthnRequest and LogoutRequest objects and validating identity provider (IdP) responses. It is designed to be used in a MVC framework to implement a SAML 2.0 service provider (SP).

## Standard

As a first step the library is aiming at, but not yet complying to OASIS SAML 2.0 SP Lite conformance. (http://docs.oasis-open.org/security/saml/v2.0/saml-conformance-2.0-os.pdf)

- Web SSO, <AuthnRequest>, HTTP redirect: check
- Web SSO, <Response>, HTTP POST: check
- Web SSO, <Response>, HTTP artifact
- Artifact Resolution, SOAP
- Enhanced Client/Proxy SSO, PAOS
- Single Logout (IdP-initiated) – HTTP redirect
- Single Logout (SP-initiated) – HTTP redirect

## Security Features

- Schema validation
- Signature validation

## Usage

### Request Authentication

This goes in a controller action:

    if (isset($_POST['SAMLResponse'])) {
        $requestID = $_SESSION['SAML.AuthnRequest.ID'];
        $raw = base64_decode($_POST['SAMLResponse']);
        $samlResponse = \Smindel\SAML\IdentityProvider\Response::fromXML($raw);
        $idpId = [IDP_ID];
        if ($samlResponse->validate($requestID, $idpId)) {
            $_SESSION['SAML.ID'] = $samlResponse->getSubjectId();
            var_dump($samlResponse->getSubject());
        } else {
            $_SESSION['SAML.ID'] = null;
            $_SESSION['SAML.AuthnRequest.ID'] = null;
            var_dump($samlResponse->getValidationError());die;
        }
    }

    if (!$_SESSION['SAML.ID']) {
        $idpUrl = [IDP_LOGIN_URL];
        $acs = Director::absoluteUrl($this->link());
        $samlRequest = \Smindel\SAML\ServiceProvider\AuthnRequest::create($idpUrl, $acs, $requestID);
        $_SESSION['SAML.AuthnRequest.ID'] = $samlRequest['ID'];

        $url = $idpUrl . '?' . http_build_query(['SAMLRequest' => $samlRequest->deflate()]);
        return $this->redirect($url);
    }
    var_dump('logged id');

## Reads

- https://en.wikipedia.org/wiki/SAML_2.0
- https://github.com/jch/saml
- https://www.owasp.org/index.php/SAML_Security_Cheat_Sheet
- https://stackoverflow.com/questions/19538561/verify-digital-signature-in-saml-response-against-certificate-in-php
- https://github.com/robrichards/xmlseclibs/blob/master/tests/xmlsec-verify.phpt

## Tools / Validators

- https://www.samltool.com/validate_authn_req.php
- http://saml.oktadev.com/

## todos

- Validation
    * replace all getElementsByTagName
    * verify certificate
    * validate response signature if present
    * validate assertion signature
    * SSL
    * NotBefore/NotOnOrAfter
    * For how long do we store request ids to prevent replay???
- Default request issuer
- Logout response
- Tests
- MetadataProvider
