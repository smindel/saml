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
        @++
        (?=(?:(?:[^"]*+"){2})*+[^"]*+$)
        (?=(?:(?:[^\']*+\'){2})*+[^\']*+$)
        (?=(?:[^\[\]]*+\[[^\[\]]*+\])*+[^\[\]]*+$)
    /x';

    public function __construct($name, $value = '', $namespaceURI = '')
    {
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
            $parents = $xpath ? $this->get($xpath) : [$this];
            foreach ($parents as $element) $element->setAttribute($attribute, $value);
        } else {
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
                $element = isset($value['ns'])
                    ? $this->ownerDocument->createElementNS($value['ns'], $name, $value['value'] ?? null)
                    : $this->ownerDocument->createElement($name, $value['value'] ?? null);
                foreach ($value['attributes'] ?? [] as $key => $val) {
                    $element->setAttribute($key, $val);
                }
                $parent->appendChild($element);
            }
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
