<?php

namespace Smindel\SAML\ServiceProvider;

class LogoutRequest extends Request
{
    protected static $tag_name = 'samlp:LogoutRequest';
    protected static $ns_uri = 'urn:oasis:names:tc:SAML:2.0:protocol';
}
