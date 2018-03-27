<?php

namespace Smindel\SAML\ServiceProvider;

use Smindel\SAML\Element;
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;

class LogoutRequest extends Element
{
    public static $count = 0;

    public static function create($destination, $subjectID, $session, $metadataProvider = null, $id = null, $spId = null)
    {
        $inst = new static('samlp:LogoutRequest', '', 'urn:oasis:names:tc:SAML:2.0:protocol');

        $inst['ID'] = $id ?: '_logout_' . (++self::$count) . '_' . uniqid();
        $inst['Version'] = '2.0';
        $inst['Destination'] = $destination;
        $inst['IssueInstant'] = date('c');

        $spId = $spId ?: $inst->defaultSpId;
        $inst->appendChild($inst->ownerDocument->createElementNS('urn:oasis:names:tc:SAML:2.0:assertion', 'saml:Issuer', $spId));

        $subject = $inst->ownerDocument->createElementNS('urn:oasis:names:tc:SAML:2.0:assertion', 'saml:NameID', $subjectID);
        if ($metadataProvider) $subject->setAttribute('SPNameQualifier', $metadataProvider);
        $subject->setAttribute('Format', 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient');
        $inst->appendChild($subject);

        $sessionIndex = $inst->ownerDocument->createElementNS('urn:oasis:names:tc:SAML:2.0:protocol', 'samlp:SessionIndex', $session);
        $inst->appendChild($sessionIndex);

        return $inst;
    }

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
        $objDSig->add509Cert(file_get_contents($certificate));

        // Append the signature to the XML
        $objDSig->insertSignature($this, $this->get('/samlp:LogoutRequest/saml:NameID')->item(0));
        // $objDSig->appendSignature($this);

        return $this;
    }

    public function validateSchema()
    {
        $libxml_display_error = function ($error)
        {
            $return = "<br/>\n";
            switch ($error->level) {
                case LIBXML_ERR_WARNING:
                    $return .= "<b>Warning $error->code</b>: ";
                    break;
                case LIBXML_ERR_ERROR:
                    $return .= "<b>Error $error->code</b>: ";
                    break;
                case LIBXML_ERR_FATAL:
                    $return .= "<b>Fatal Error $error->code</b>: ";
                    break;
            }
            $return .= trim($error->message);
            if ($error->file) {
                $return .=    " in <b>$error->file</b>";
            }
            $return .= " on line <b>$error->line</b>\n";

            return $return;
        };

        $libxml_display_errors = function () use ($libxml_display_error) {
            $errors = libxml_get_errors();
            foreach ($errors as $error) {
                print $libxml_display_error($error);
            }
            libxml_clear_errors();
        };

        // Enable user error handling
        libxml_use_internal_errors(true);

        if (!$this->ownerDocument->schemaValidate(dirname(dirname(dirname(__FILE__))) . '/schema/saml-schema-protocol-2.0.xsd')) {
            print '<b>DOMDocument::schemaValidate() Generated Errors!</b>';
            $libxml_display_errors();
        }
    }

    public function deflate()
    {
        file_put_contents('../LogoutRequest.xml', $this->ownerDocument->saveXML());
        return base64_encode(preg_replace('/(\s{2,})/', ' ', $this->ownerDocument->saveXML()));
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
