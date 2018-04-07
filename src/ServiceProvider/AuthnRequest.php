<?php

namespace Smindel\SAML\ServiceProvider;

class AuthnRequest extends Request
{
    public static function create($destination, $acs = null, $id = null, $spId = null)
    {
        $inst = new static('samlp:AuthnRequest', '', 'urn:oasis:names:tc:SAML:2.0:protocol');

        $inst['@ID'] = $id ?: '_authn_' . uniqid();
        $inst['@Version'] = '2.0';
        $inst['@Destination'] = $destination;
        $inst['@IssueInstant'] = date('c');
        $inst['@ProtocolBinding'] = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST';
        $inst['@AssertionConsumerServiceURL'] = $acs ?: $_SERVER['REQUEST_SCHEME'] . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];

        $inst['saml:Issuer'] = [
            'ns' => 'urn:oasis:names:tc:SAML:2.0:assertion',
            'value' => $spId ?: $inst->defaultSpId,
        ];

        return $inst;
    }
}
