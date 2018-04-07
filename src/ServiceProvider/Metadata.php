<?php

namespace Smindel\SAML\ServiceProvider;

use Smindel\SAML\Element;

class Metadata extends Element
{
    public static function create($entityId = null)
    {
        $inst = new static('md:EntityDescriptor', '', 'urn:oasis:names:tc:SAML:2.0:metadata');

        $inst['@validUntil'] = date('c', strtotime('+2 days'));
        $inst['@cacheDuration'] = sprintf('PT%dS', 60*60*24*7);
        $inst['@entityID'] = $entityId ?: 'BORIS';

        $inst['md:SPSSODescriptor'] = [
            '@AuthnRequestsSigned' => 'false',
            '@WantAssertionsSigned' => 'false',
            '@protocolSupportEnumeration' => 'urn:oasis:names:tc:SAML:2.0:protocol',
        ];


        $inst['md:SPSSODescriptor/md:SingleLogoutService'] = [
            '@Binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
            '@Location' => 'http://slo-endpoint',
        ];

        $inst['md:SPSSODescriptor/md:NameIDFormat'] = 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified';

        $inst['md:SPSSODescriptor/md:AssertionConsumerService'] = [
            '@Binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
            '@Location' => 'http://acs-endpoint',
            '@index' => 1,
        ];

        return $inst;
    }

}
