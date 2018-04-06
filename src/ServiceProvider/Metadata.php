<?php

namespace Smindel\SAML\ServiceProvider;

use Smindel\SAML\Element;

class Metadata extends Element
{
    public static function create($entityId = null)
    {
        $inst = new static('md:EntityDescriptor', '', 'urn:oasis:names:tc:SAML:2.0:metadata');

        $inst['validUntil'] = date('c', strtotime('+2 days'));
        $inst['cacheDuration'] = sprintf('PT%dS', 60*60*24*7);
        $inst['entityID'] = $entityId ?: 'BORIS';

        $spSsoDesc = $inst->ownerDocument->createElement('md:SPSSODescriptor');
        $spSsoDesc->setAttribute('AuthnRequestsSigned', 'false');
        $spSsoDesc->setAttribute('WantAssertionsSigned', 'false');
        $spSsoDesc->setAttribute('protocolSupportEnumeration', 'urn:oasis:names:tc:SAML:2.0:protocol');

        $slo = $inst->ownerDocument->createElement('md:SingleLogoutService');
        $slo->setAttribute('Binding', 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect');
        $slo->setAttribute('Location', 'http://slo-endpoint');

        $nameIdFormat = $inst->ownerDocument->createElement('md:NameIDFormat', 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified');

        $acs = $inst->ownerDocument->createElement('md:AssertionConsumerService');
        $acs->setAttribute('Binding', 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST');
        $acs->setAttribute('Location', 'http://acs-endpoint');
        $acs->setAttribute('index', 1);

        $spSsoDesc->appendChild($slo);
        $spSsoDesc->appendChild($nameIdFormat);
        $spSsoDesc->appendChild($acs);
        $inst->appendChild($spSsoDesc);

        return $inst;
    }

}
