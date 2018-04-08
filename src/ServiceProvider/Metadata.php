<?php

namespace Smindel\SAML\ServiceProvider;

use Smindel\SAML\Element;

class Metadata extends Element
{
    protected static $tag_name = 'md:EntityDescriptor';
    protected static $ns_uri = 'urn:oasis:names:tc:SAML:2.0:metadata';
    protected static $schema_file = 'saml-schema-metadata-2.0.xsd';
}
