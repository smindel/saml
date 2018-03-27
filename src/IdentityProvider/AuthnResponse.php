<?php

namespace Smindel\SAML\IdentityProvider;

use Smindel\SAML\Element;

class AuthnResponse extends Element
{
    protected $validationErrors = [];

    public function getSubjectId()
    {
        $node = $this->get('/samlp:Response/saml:Assertion/saml:Subject/saml:NameID')->item(0);
        if ($node) return $node->nodeValue;
    }

    public function getSubject()
    {
        $subject = [];
        foreach ($this->get('/samlp:Response/saml:Assertion/saml:AttributeStatement/saml:Attribute[@Name]') as $attribute) {
            if ($value = $this->get('saml2:AttributeValue', $attribute)->item(0)) $subject[$attribute->getAttribute('Name')] = $value->nodeValue;
        }
        return $subject;
    }

    public function getSessionIndex()
    {
        $stmt = $this->get('/samlp:Response/saml:Assertion/saml:AuthnStatement[@SessionIndex]')->item(0);
        return $stmt ? $stmt->getAttribute('SessionIndex') : null;
    }

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

        if (!$this->validateAssertion()) return !($this->validationErrors[] = 'invalid assertion');

        if (!$this->validateConditions()) return !($this->validationErrors[] = 'invalid conditions');

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

    public function validateAssertion()
    {
        $assertion = $this->get('/samlp:Response/saml:Assertion')->item(0);

        if ($this->getIssuer() != $this->getIssuer($assertion)) return !($this->validationErrors[] = 'invalid assertion issuer');

        if (!$this->validateSubject()) return !($this->validationErrors[] = 'invalid assertion subject');

        if (!$this->validateSignature($assertion)) return !($this->validationErrors[] = 'invalid assertion signature');

        return true;
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

    public function validateSubject($recipient = null)
    {
        $recipient = $recipient ?: $this->currentUrl;
        $node = $this->get('/samlp:Response/saml:Assertion/saml:Subject/saml:SubjectConfirmation[@Method=\'urn:oasis:names:tc:SAML:2.0:cm:bearer\']')->item(0);
        if (!$node) return !($this->validationErrors[] = 'missing or invalid assertion subject confirmation');
        $data = $this->get('saml:SubjectConfirmationData[@NotOnOrAfter][@Recipient]', $node)->item(0);
        if (!$data) return !($this->validationErrors[] = 'missing or invalid assertion subject confirmation data');
        if (strtotime($data->getAttribute('NotOnOrAfter')) <= time()) return !($this->validationErrors[] = 'assertion expired');
        if ($data->getAttribute('Recipient') != $recipient) return !($this->validationErrors[] = 'invalid assertion subject confirmation data recipient');

        return true;
    }

    public function validateConditions($audience = null)
    {
        $audience = $audience ?: $this->defaultSpId;
        $conditions = $this->get('/samlp:Response/saml:Assertion/saml:Conditions')->item(0);
        if (!$conditions) return true;
        if (($notbefore = $conditions->getAttribute('NotBefore')) && strtotime($notbefore) > time()) return !($this->validationErrors[] = 'assertion not yet active');
        if (($notonorafter = $conditions->getAttribute('NotOnOrAfter')) && strtotime($notonorafter) <= time()) return !($this->validationErrors[] = 'assertion expired');
        $audiences = $this->get('saml:AudienceRestriction/saml:Audience', $conditions);
        $audienceConfirmed = $audiences->length ? false : null;

        foreach ($audiences as $value) {
            if ($value->nodeValue == $audience) {
                $audienceConfirmed = true;
                break;
            }
        }

        return $audienceConfirmed == false ? !($this->validationErrors[] = 'invalid assertion audience') : true;
    }
}
