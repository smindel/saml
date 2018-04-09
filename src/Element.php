<?php

namespace Smindel\SAML;
use DOMElement;
use ArrayAccess;

class Element extends DOMElement implements ArrayAccess
{
    protected $xpath;
    protected $defaultSpId;
    protected $currentUrl;
    protected static $regex = '/
        \/?@++
        (?=(?:(?:[^"]*+"){2})*+[^"]*+$)
        (?=(?:(?:[^\']*+\'){2})*+[^\']*+$)
        (?=(?:[^\[\]]*+\[[^\[\]]*+\])*+[^\[\]]*+$)
    /x';
    public static $namespace_uris = [
        'samlp' => 'urn:oasis:names:tc:SAML:2.0:protocol',
        'saml' => 'urn:oasis:names:tc:SAML:2.0:assertion',
        'ds' => 'http://www.w3.org/2000/09/xmldsig#',
        'md' => 'urn:oasis:names:tc:SAML:2.0:metadata',
    ];

    public function __construct($name = null, $value = '', $namespaceURI = '')
    {
        $name = $name ?: static::$tag_name;
        $namespaceURI = $namespaceURI ?: static::$ns_uri;
        parent::__construct($name, $value, $namespaceURI);
        $dom = new \DOMDocument('1.0', 'utf-8');
        $dom->appendChild($this);
        $this->init();
    }

    private function init()
    {
        $this->defaultSpId = sprintf('%s://%s/', self::is_ssl() ? 'https' : 'http', $_SERVER['HTTP_HOST']);
        $this->currentUrl = $this->defaultSpId . ltrim($_SERVER['REQUEST_URI'], '/');

        list($prefix) = explode(':', $this->tagName);

        $this->xpath = new \DOMXPath($this->ownerDocument);
        $this->xpath->registerNamespace($prefix, $this->lookupNamespaceUri($prefix));
        $this->xpath->registerNamespace('samlp', 'urn:oasis:names:tc:SAML:2.0:protocol');
        $this->xpath->registerNamespace('saml', 'urn:oasis:names:tc:SAML:2.0:assertion');
        $this->xpath->registerNamespace('ds', 'http://www.w3.org/2000/09/xmldsig#');
    }

    public function lookupNamespaceUri($prefix)
    {
        return parent::lookupNamespaceUri($prefix) ?: self::$namespace_uris[$prefix];
    }

    public static function fromXML($xml)
    {
        $dom = new \DOMDocument('1.0', 'utf-8');
        $dom->registerNodeClass('DOMElement', static::class);
        $dom->loadXML($xml, LIBXML_DTDLOAD|LIBXML_DTDVALID);
        $element = $dom->documentElement;
        $dom->registerNodeClass('DOMElement', null);
        $element->init();
        return $element;
    }

    public function toXML()
    {
        return $this->ownerDocument->saveXML();
    }

    public function validateSchema()
    {
        $filename = dirname(dirname(__FILE__)) . '/schema/' . static::$schema_file;
        return (bool)$this->ownerDocument->schemaValidate($filename);
    }

    public function get($xpath, $node = null, $registerNs = true)
    {
        return $this->xpath->query($xpath, $node, $registerNs);
    }

    public function offsetExists($offset)
    {
        return (bool)$this->get($offset)->length;
    }

    public function offsetGet($offset)
    {
        $node = $this->get($offset)->item(0);
        if ($node instanceof \DOMAttr) return $node->value;
        if ($node instanceof \DOMText) return $node->textContent;
        return $node;
    }

    public function offsetSet($offset, $value)
    {
        list($xpath, $attribute) = preg_split(static::$regex, $offset . '@');
        if ($attribute && !is_array($value)) {
            // set attribute
            $parents = $xpath ? $this->get($xpath) : [$this];
            foreach ($parents as $element) {
                $this->setElementattribute($element, $attribute, $value);
            }
        } else if ($value instanceof \DOMNode) {
            $segments = explode('/', $xpath);
            $name = array_pop($segments);
            $xpath = implode('/', $segments);
            $parent = $xpath ? $this->get($xpath)->item(0) : $this;
            $value = $this->ownerDocument->importNode($value, true);
            $parent->appendChild($value);
        } else {
            // create element
            $segments = explode('/', $xpath);
            $name = array_pop($segments);
            $xpath = implode('/', $segments);
            $parents = $xpath ? $this->get($xpath) : [$this];
            if (!is_array($value)) $value = ['value' => $value];
            if (empty($value['ns'])) $value['ns'] = $this->lookupNamespaceUri(explode(':', $name)[0]);
            foreach ($value as $key => $val) {
                if ($key[0] == '@') {
                    $value['attributes'][substr($key,1)]  = $val;
                    unset($value[$key]);
                }
            }
            foreach ($parents as $parent) {
                // $element = isset($value['ns'])
                //     ? $this->ownerDocument->createElementNS($value['ns'], $name, $value['value'] ?? null)
                //     : $this->ownerDocument->createElement($name, $value['value'] ?? null);
                $element = $this->ownerDocument->createElementNS($value['ns'], $name, $value['value'] ?? null);
                foreach ($value['attributes'] ?? [] as $key => $val) {
                    $this->setElementattribute($element, $key, $val);
                }
                $parent->appendChild($element);
            }
        }
    }

    protected function setElementattribute($node, $attributeName, $attributeValue)
    {
        $segments = explode(':', $attributeName);
        $name = array_pop($segments);
        $prefix = array_pop($segments);
        if ($prefix) {
            $node->setAttributeNS($this->lookupNamespaceUri($prefix), $attributeName, $attributeValue);
        } else {
            $node->setAttribute($attributeName, $attributeValue);
        }
    }

    public function offsetUnset($offset)
    {
        foreach ($this->get($offset) as $node) {
            $node->parentNode->removeChild($node);
        }
    }

    protected static function is_ssl()
    {
        if (isset($_SERVER['REQUEST_SCHEME']) && $_SERVER['REQUEST_SCHEME'] == 'https') return true;
        if (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] != 'off') return true;
        if (isset($_SERVER['SSL'])) return true;
    }
}
