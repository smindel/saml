<?php

namespace Smindel\SAML\ServiceProvider;

use Psr\Container\ContainerInterface;
use Smindel\SAML\SamlServiceConfigItemNotFound;
use Psr\Container\ContainerExceptionInterface;

class ServiceProvider implements ContainerInterface
{
    const BINDING_POST = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST';
    const BINDING_REDIRECT = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect';

    protected $idp;
    protected $sp;
    protected $pkey;
    protected $container;

    public function __construct($idpEntityDescriptor = null, $spEntityDescriptor = null, $spPrivateKey = null)
    {
        $this->idp = $idpEntityDescriptor;
        $this->sp = $spEntityDescriptor;
        $this->pkey = $spPrivateKey;
    }

    /**
     * Finds an entry of the container by its identifier and returns it.
     *
     * @param string $id Identifier of the entry to look for.
     *
     * @throws SamlServiceConfigItemNotFound  No entry was found for **this** identifier.
     * @throws ContainerExceptionInterface Error while retrieving the entry.
     *
     * @return mixed Entry.
     */
    public function get($id)
    {
        if (isset($this->container[$id])) return $this->container[$id];
        if (method_exists($this, $methodName = $id . 'Factory')) return $this->$methodName();
        list($domain, $xpath) = explode(';', $id . ';');
        if (!in_array($domain, ['idp', 'sp'])) throw new SamlServiceConfigItemNotFound(sprintf('Cannot find entry for "%s" in %s', $id, self::class));
        return $this->$domain[$xpath];
    }

    /**
     * Returns true if the container can return an entry for the given identifier.
     * Returns false otherwise.
     *
     * `has($id)` returning true does not mean that `get($id)` will not throw an exception.
     * It does however mean that `get($id)` will not throw a `SamlServiceConfigItemNotFound`.
     *
     * @param string $id Identifier of the entry to look for.
     *
     * @return bool
     */
    public function has($id)
    {
        if (isset($this->container[$id]) || method_exists($this, $methodName = $id . 'Factory')) return true;
        list($domain, $xpath) = explode(';', $id . ';');
        if (in_array($domain, ['idp', 'sp']) && ($meta = $this->$domain) && isset($meta[$xpath])) return true;
        return false;
    }

    public function set($id, $value)
    {
        $this->container[$id] = $value;
    }


    public function or($id, $fallback)
    {
        return $this->has($id) ? $this->get($id) : $fallback;
    }

    public function MetadataFactory()
    {
        $inst = new Metadata;

        $inst['@validUntil'] = date('c', strtotime('+' . $this->or('sp;md.validFor', '2 days')));
        $inst['@cacheDuration'] = $this->or('sp;@cacheDuration', sprintf('PT%dS', 60*60*24*7));
        $inst['@entityID'] = $this->or('sp;@entityID', $_SERVER['HTTP_HOST']);

        $inst['md:SPSSODescriptor'] = [
            '@AuthnRequestsSigned' => $this->or('sp;md:SPSSODescriptor/@AuthnRequestsSigned', 'false'),
            '@WantAssertionsSigned' => $this->or('sp;md:SPSSODescriptor/@WantAssertionsSigned', 'false'),
            '@protocolSupportEnumeration' => $this->or('sp;md:SPSSODescriptor/@protocolSupportEnumeration', 'urn:oasis:names:tc:SAML:2.0:protocol'),
        ];

        if ($this->pkey && $this->has('sp;md:SPSSODescriptor/md:KeyDescriptor[@use=\'signing\']/ds:KeyInfo/ds:X509Data/ds:X509Certificate/text()')) {
            // optional
            $inst['md:SPSSODescriptor/md:KeyDescriptor'] = [
                '@use' => 'signing',
            ];
            $inst['md:SPSSODescriptor/md:KeyDescriptor[@use=\'signing\']/ds:KeyInfo'] = [
                'ns' => 'http://www.w3.org/2000/09/xmldsig#',
            ];
            $inst['md:SPSSODescriptor/md:KeyDescriptor[@use=\'signing\']/ds:KeyInfo/ds:X509Data'] = [
                'ns' => 'http://www.w3.org/2000/09/xmldsig#',
            ];
            $inst['md:SPSSODescriptor/md:KeyDescriptor[@use=\'signing\']/ds:KeyInfo/ds:X509Data/ds:X509Certificate'] = [
                'ns' => 'http://www.w3.org/2000/09/xmldsig#',
                'value' => $this->get('sp;md:SPSSODescriptor/md:KeyDescriptor[@use=\'signing\']/ds:KeyInfo/ds:X509Data/ds:X509Certificate/text()'),
            ];
        }

        if ($this->pkey && $this->has('sp;md:SPSSODescriptor/md:KeyDescriptor[@use=\'encryption\']/ds:KeyInfo/ds:X509Data/ds:X509Certificate/text()')) {
            // optional
            $inst['md:SPSSODescriptor/md:KeyDescriptor'] = [
                '@use' => 'encryption',
            ];
            $inst['md:SPSSODescriptor/md:KeyDescriptor[@use=\'encryption\']/ds:KeyInfo'] = [
                'ns' => 'http://www.w3.org/2000/09/xmldsig#',
            ];
            $inst['md:SPSSODescriptor/md:KeyDescriptor[@use=\'encryption\']/ds:KeyInfo/ds:X509Data'] = [
                'ns' => 'http://www.w3.org/2000/09/xmldsig#',
            ];
            $inst['md:SPSSODescriptor/md:KeyDescriptor[@use=\'encryption\']/ds:KeyInfo/ds:X509Data/ds:X509Certificate'] = [
                'ns' => 'http://www.w3.org/2000/09/xmldsig#',
                'value' => $this->get('sp;md:SPSSODescriptor/md:KeyDescriptor[@use=\'encryption\']/ds:KeyInfo/ds:X509Data/ds:X509Certificate/text()'),
            ];
        }

        $inst['md:SPSSODescriptor/md:SingleLogoutService'] = [
            '@Binding' => $this->or('slo.binding', self::BINDING_POST),
            '@Location' => $this->or('slo.url', (self::is_ssl() ? 'https://' : 'http://') . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI']),
        ];

        $i = 1;
        while ($this->has("sp;md:SPSSODescriptor/md:NameIDFormat[$i]")) {
            $inst["md:SPSSODescriptor/md:NameIDFormat[$i]"] = $this->get("sp;md:SPSSODescriptor/md:NameIDFormat[$i]");
            $i++;
        }

        $inst['md:SPSSODescriptor/md:AssertionConsumerService'] = [
            '@Binding' => $this->or('acs.binding', self::BINDING_POST),
            '@Location' => $this->or('acs.url', (self::is_ssl() ? 'https://' : 'http://') . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI']),
            '@index' => 1,
        ];

        if ($this->has('sp;md:Organization')) {
            $inst['md:Organization'] = $this->get('sp;md:Organization');
        }

        $i = 1;
        while ($this->has("sp;md:ContactPerson[$i]")) {
            $inst["md:ContactPerson[$i]"] = $this->get("sp;md:ContactPerson[$i]");
            $i++;
        }

        return $inst;
    }

    public function AuthnRequestFactory()
    {
        $inst = new AuthnRequest;

        $inst['@ID'] = $this->or('AuthnRequest.ID', '_authn_' . uniqid());
        $inst['@Version'] = '2.0';
        $inst['@Destination'] = $this->get("idp;md:IDPSSODescriptor/md:SingleSignOnService[@Binding='" . self::BINDING_POST . "']/@Location");
        $inst['@IssueInstant'] = date('c');
        $inst['@ProtocolBinding'] = $this->or('acs.binding', self::BINDING_POST);
        $inst['@AssertionConsumerServiceURL'] = $this->or('acs.url', (self::is_ssl() ? 'https://' : 'http://') . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI']);

        $inst['saml:Issuer'] = [
            'ns' => 'urn:oasis:names:tc:SAML:2.0:assertion',
            'value' => $this->or('sp;@entityID', $_SERVER['HTTP_HOST']),
        ];

        return $inst;
    }

    protected static function is_ssl()
    {
        if (isset($_SERVER['REQUEST_SCHEME']) && $_SERVER['REQUEST_SCHEME'] == 'https') return true;
        if (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] != 'off') return true;
        if (isset($_SERVER['SSL'])) return true;
    }
}
