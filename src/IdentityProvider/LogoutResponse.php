<?php

namespace Smindel\SAML\IdentityProvider;

use Smindel\SAML\Element;

class LogoutResponse extends Element
{
    protected $validationErrors = [];

    public function getIssuer($context = null)
    {
        $context = $context ?: $this->get('/samlp:Response')->item(0);
        $node = $this->get('saml:Issuer', $context)->item(0);
        if ($node) return $node->nodeValue;
    }

    public function getValidationError()
    {
        return implode(', ', $this->validationErrors);
    }

    public function validate($requestID = null, $issuer = null)
    {
        $xpath = new \DOMXPath($this->ownerDocument);

        if (!$this->validateSchema()) return !($this->validationErrors[] = 'invalid schema');

        if (!$this->validateSignature()) return !($this->validationErrors[] = 'invalid response signature');

        if ($requestID && $this['InResponseTo'] != $requestID) return !($this->validationErrors[] = 'invalid request id');

        if (!$this->validateStatus()) return !($this->validationErrors[] = 'invalid status');

        if (!$this->validateIssuer($issuer)) return !($this->validationErrors[] = 'invalid issuer');

        return true;
    }

    public function validateSchema()
    {
        return (bool)$this->ownerDocument->schemaValidate(dirname(dirname(dirname(__FILE__))) . '/schema/saml-schema-protocol-2.0.xsd');
    }

    public function validateStatus()
    {
        return $this->get('/samlp:Response/samlp:Status/samlp:StatusCode[@Value=\'urn:oasis:names:tc:SAML:2.0:status:Success\']')->length == 1;
    }

    public function validateIssuer($issuer = null)
    {
        $issuer = $issuer ?: $this->defaultSpId;
        return $this->getIssuer() == $issuer;
    }

    public function validateSignature($context = null)
    {
        $context = $context ?: $this->get('/samlp:Response')->item(0);
        $signature = $this->get('ds:Signature', $context)->item(0);
        if (!$signature) return !($this->validationErrors[] = 'missing signature');

        $data = $this->get('ds:SignedInfo', $signature)->item(0);
        if (!$data) return !($this->validationErrors[] = 'missing signed info');
        $data = $data->C14N(true, false);

        $value = $this->get('ds:SignatureValue', $signature)->item(0);
        if (!$value) return !($this->validationErrors[] = 'missing signature value');
        $value = base64_decode($value->nodeValue);

        $certificate = $this->get('ds:KeyInfo/ds:X509Data/ds:X509Certificate', $signature)->item(0);
        if (!$certificate) return !($this->validationErrors[] = 'missing x509 certificate');
        $certificate = "-----BEGIN CERTIFICATE-----\n" . $certificate->nodeValue . "\n" . "-----END CERTIFICATE-----";

        $algorithm = $this->get('ds:SignedInfo/ds:SignatureMethod[@Algorithm]', $signature)->item(0);
        if (!$algorithm) return !($this->validationErrors[] = 'missing or invalid signature method');
        list(,$algorithm) = explode('#', $algorithm->getAttribute('Algorithm'));
        $algorithm = strtoupper($algorithm);

        return openssl_verify($data, $value, $certificate, $algorithm) == 1;
    }
}
