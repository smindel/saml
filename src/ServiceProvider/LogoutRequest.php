<?php

namespace Smindel\SAML\ServiceProvider;

class LogoutRequest extends Request
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
}
