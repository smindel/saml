<?php

namespace Smindel\SAML\ServiceProvider;

class AuthnRequest extends Request
{
    protected static $tag_name = 'samlp:AuthnRequest';
    protected static $ns_uri = 'urn:oasis:names:tc:SAML:2.0:protocol';
}
