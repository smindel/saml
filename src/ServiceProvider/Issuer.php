<?php

namespace Smindel\SAML\ServiceProvider;

use Smindel\SAML\Element;

class Issuer extends Element
{
    public static function create(string $content)
    {
        return new static('saml:Issuer', $content, 'urn:oasis:names:tc:SAML:2.0:assertion');
    }
}
