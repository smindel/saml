<?php

namespace Smindel\SAML;
use DOMElement;
use ArrayAccess;

class Element extends DOMElement implements ArrayAccess
{
    protected $dom;
    protected $xpath;
    protected $defaultSpId;
    protected $currentUrl;

    public function __construct($name, $value = '', $namespaceURI = '')
    {
        parent::__construct($name, $value, $namespaceURI);
        $this->dom = new \DOMDocument('1.0', 'utf-8');
        $this->dom->appendChild($this);
        $this->init();
    }

    private function init()
    {
        $this->defaultSpId = sprintf('%s://%s/', $_SERVER['REQUEST_SCHEME'], $_SERVER['HTTP_HOST']);
        $this->currentUrl = $this->defaultSpId . ltrim($_SERVER['REQUEST_URI'], '/');

        $this->xpath = new \DOMXPath($this->dom);
        $this->xpath->registerNamespace('samlp', 'urn:oasis:names:tc:SAML:2.0:protocol');
        $this->xpath->registerNamespace('saml', 'urn:oasis:names:tc:SAML:2.0:assertion');
        $this->xpath->registerNamespace('ds', 'http://www.w3.org/2000/09/xmldsig#');
    }

    public static function fromXML($xml)
    {
        $dom = new \DOMDocument('1.0', 'utf-8');
        $dom->registerNodeClass('DOMElement', static::class);
        $dom->loadXML($xml, LIBXML_DTDLOAD|LIBXML_DTDVALID);
        $element = $dom->firstChild;
        $element->dom = $dom;
        $dom->registerNodeClass('DOMElement', null);
        $element->init();
        return $element;
    }

    public function get($xpath, $node = null, $registerNs = true)
    {
        return $this->xpath->query($xpath, $node, $registerNs);
    }

    public function offsetExists($offset)
    {
        return $this->hasAttribute($offset);
    }

    public function offsetGet($offset)
    {
        return $this->getAttribute($offset);
    }

    public function offsetSet($offset, $value)
    {
        $this->setAttribute($offset, $value);
        if (strtolower($offset) == 'id') $this->setIDAttribute($offset, true);
    }

    public function offsetUnset($offset)
    {
        $this->removeAttribute($offset);
    }
}
