<?php

namespace Smindel\SAML\ServiceProvider;

use Smindel\SAML\Element;

class AuthNRequest extends Element
{
    public static function create($destination, $acs = null, $id = null, $spId = null)
    {
        $inst = new static('samlp:AuthnRequest', '', 'urn:oasis:names:tc:SAML:2.0:protocol');

        $inst['ID'] = $id ?: '_authn_' . uniqid();
        $inst['Version'] = '2.0';
        $inst['Destination'] = $destination;
        $inst['IssueInstant'] = date('c');
        $inst['ProtocolBinding'] = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST';
        $inst['AssertionConsumerServiceURL'] = $acs ?: $_SERVER['REQUEST_SCHEME'] . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];

        $spId = $spId ?: $inst->defaultSpId;
        $inst->appendChild($inst->ownerDocument->createElementNS('urn:oasis:names:tc:SAML:2.0:assertion', 'saml:Issuer', $spId));

        return $inst;
    }

    public function deflate()
    {
        return base64_encode(preg_replace('/(\s{2,})/', ' ', $this->ownerDocument->saveXML()));
    }
}
