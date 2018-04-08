<?php

namespace Smindel\SAML\ServiceProvider;

class AuthnResponse extends Response
{
    protected static $tag_name = 'samlp:AuthnRequest';
    protected static $ns_uri = 'urn:oasis:names:tc:SAML:2.0:protocol';

    public function getSubjectId()
    {
        return $this['saml:Assertion/saml:Subject/saml:NameID/text()'];
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
        return $this['saml:Assertion/saml:AuthnStatement[@SessionIndex]/@SessionIndex'];
    }

    public function validate($requestID = null, $issuer = null, $audience = null)
    {
        $xpath = new \DOMXPath($this->ownerDocument);

        if (!$this->validateSchema()) return !($this->validationErrors[] = 'invalid schema');

        if (!$this->validateSignature()) return !($this->validationErrors[] = 'invalid response signature');

        if ($requestID && $this['@InResponseTo'] != $requestID) return !($this->validationErrors[] = 'invalid request id');

        if (!$this->validateStatus()) return !($this->validationErrors[] = 'invalid status');

        if (!$this->validateIssuer($issuer)) return !($this->validationErrors[] = 'invalid issuer');

        if (!$this->validateAssertion()) return !($this->validationErrors[] = 'invalid assertion');

        if (!$this->validateConditions($audience)) return !($this->validationErrors[] = 'invalid conditions');

        return true;
    }

    public function validateAssertion()
    {
        if ($this->getIssuer() != $this->getIssuer('saml:Assertion/')) return !($this->validationErrors[] = 'invalid assertion issuer');

        if (!$this->validateSubject()) return !($this->validationErrors[] = 'invalid assertion subject');

        if (!$this->validateSignature('saml:Assertion/')) return !($this->validationErrors[] = 'invalid assertion signature');

        return true;
    }

    public function validateSubject($recipient = null)
    {
        $confPath = 'saml:Assertion/saml:Subject/saml:SubjectConfirmation[@Method=\'urn:oasis:names:tc:SAML:2.0:cm:bearer\']';
        $node = $this[$confPath];
        if (!$node) return !($this->validationErrors[] = 'missing or invalid assertion subject confirmation');

        $data = $this[$confPath . '/saml:SubjectConfirmationData[@NotOnOrAfter][@Recipient]'];
        if (!$data) return !($this->validationErrors[] = 'missing or invalid assertion subject confirmation data');

        if (strtotime($data->getAttribute('NotOnOrAfter')) <= time()) return !($this->validationErrors[] = 'assertion expired');

        $recipient = $recipient ?: $this->currentUrl;
        if ($data->getAttribute('Recipient') != $recipient) return !($this->validationErrors[] = 'invalid assertion subject confirmation data recipient');

        return true;
    }

    public function validateConditions($audience = null)
    {
        $conditions = $this['saml:Assertion/saml:Conditions'];
        if (!$conditions) return true;
        if (($notbefore = $conditions->getAttribute('NotBefore')) && strtotime($notbefore) > time()) return !($this->validationErrors[] = 'assertion not yet active');
        if (($notonorafter = $conditions->getAttribute('NotOnOrAfter')) && strtotime($notonorafter) <= time()) return !($this->validationErrors[] = 'assertion expired');

        $audience = $audience ?: $this->defaultSpId;
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
