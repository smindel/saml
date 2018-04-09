<?php

namespace Smindel\SAML\ServiceProvider;

use Smindel\SAML\Element;
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;

class Request extends Element
{
    protected static $schema_file = 'saml-schema-protocol-2.0.xsd';

    public function sign($privateKey, $certificate)
    {
        // Create a new Security object
        $objDSig = new XMLSecurityDSig();
        // Use the c14n exclusive canonicalization
        $objDSig->setCanonicalMethod(XMLSecurityDSig::EXC_C14N);
        // Sign using SHA-256
        $objDSig->addReference(
            $this->ownerDocument,
            XMLSecurityDSig::SHA256,
            [
                'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
                'http://www.w3.org/2001/10/xml-exc-c14n#'
            ]
        );

        // Create a new (private) Security key
        $objKey = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, array('type'=>'private'));
        /*
        If key has a passphrase, set it using
        $objKey->passphrase = '<passphrase>';
        */
        // Load the private key
        $objKey->loadKey($privateKey, TRUE);

        // Sign the XML file
        $objDSig->sign($objKey);

        // Add the associated public key to the signature
        $objDSig->add509Cert($certificate);

        // Append the signature to the XML
        $objDSig->insertSignature($this, $this['saml:NameID']);

        return $this;
    }

    public function deflate()
    {
        return base64_encode(preg_replace('/(\s{2,})/', ' ', $this->toXML()));
    }

    public function redirectBinding($destination)
    {
        return $destination . '?' . http_build_query(['SAMLRequest' => $this->deflate()]);
    }

    public function postBinding($destination)
    {
        $base64Request = $this->deflate();
        $raw = <<<RAW
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
<head><meta http-equiv="content-type" content="text/html; charset=utf-8" /></head>
<body onload="document.getElementById('saml-request-form').submit();">
    <form id="saml-request-form" method="post" action="%s"><input name="SAMLRequest" value="$base64Request" type="hidden"/></form>
</body>
</html>
RAW;
        return sprintf($raw, $destination);
    }
}
