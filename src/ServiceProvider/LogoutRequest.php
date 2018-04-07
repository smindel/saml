<?php

namespace Smindel\SAML\ServiceProvider;

class LogoutRequest extends Request
{
    public static $count = 0;

    public static function create($destination, $subjectID, $session, $metadataProvider = null, $id = null, $spId = null)
    {
        $inst = new static('samlp:LogoutRequest', '', 'urn:oasis:names:tc:SAML:2.0:protocol');

        $inst['@ID'] = $id ?: '_logout_' . (++self::$count) . '_' . uniqid();
        $inst['@Version'] = '2.0';
        $inst['@Destination'] = $destination;
        $inst['@IssueInstant'] = date('c');

        $inst['saml:Issuer'] = $spId ?: $inst->defaultSpId;

        $inst['saml:NameID'] = [
            'value' => $subjectID,
            '@Format' => 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient'
        ];
        if ($metadataProvider) $inst['saml:NameID@SPNameQualifier'] = $metadataProvider;

        $inst['samlp:SessionIndex'] = $session;

        return $inst;
    }
}
