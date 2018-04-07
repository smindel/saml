<?php

namespace Smindel\SAML\ServiceProvider;

use Smindel\SAML\Element;

class Response extends Element
{
    public function getIssuer($context = null)
    {
        return $this[$context . 'saml:Issuer/text()'];
    }

    protected $validationErrors = [];

    public function getValidationError()
    {
        return implode(', ', $this->validationErrors);
    }

    public function validateSignature($context = null)
    {
        if (!$this[$context . 'ds:Signature']) return !($this->validationErrors[] = 'missing signature');

        $data = $this[$context . 'ds:Signature/ds:SignedInfo'];
        if (!$data) return !($this->validationErrors[] = 'missing signed info');
        $data = $data->C14N(true, false);

        $value = $this[$context . 'ds:Signature/ds:SignatureValue'];
        if (!$value) return !($this->validationErrors[] = 'missing signature value');
        $value = base64_decode($value->nodeValue);

        $certificate = $this[$context . 'ds:Signature/ds:KeyInfo/ds:X509Data/ds:X509Certificate'];
        if (!$certificate) return !($this->validationErrors[] = 'missing x509 certificate');
        $certificate = "-----BEGIN CERTIFICATE-----\n" . $certificate->nodeValue . "\n" . "-----END CERTIFICATE-----";

        $algorithm = $this[$context . 'ds:Signature/ds:SignedInfo/ds:SignatureMethod[@Algorithm]'];
        if (!$algorithm) return !($this->validationErrors[] = 'missing or invalid signature method');
        list(,$algorithm) = explode('#', $algorithm->getAttribute('Algorithm'));
        $algorithm = strtoupper($algorithm);

        return openssl_verify($data, $value, $certificate, $algorithm) == 1;
    }

    public function validateSchema()
    {
        return (bool)$this->ownerDocument->schemaValidate(dirname(dirname(dirname(__FILE__))) . '/schema/saml-schema-protocol-2.0.xsd');
    }

    public function validateStatus()
    {
        return (bool)$this['samlp:Status/samlp:StatusCode[@Value=\'urn:oasis:names:tc:SAML:2.0:status:Success\']'];
    }

    public function validateIssuer($issuer = null)
    {
        $issuer = $issuer ?: $this->defaultSpId;
        return $this->getIssuer() == $issuer;
    }

}
