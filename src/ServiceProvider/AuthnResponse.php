<?php

namespace Smindel\SAML\ServiceProvider;

class AuthnResponse extends Response
{
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
        $assertion = $this->get('/samlp:Response/saml:Assertion')->item(0);

        if ($this->getIssuer() != $this->getIssuer($assertion)) return !($this->validationErrors[] = 'invalid assertion issuer');

        if (!$this->validateSubject()) return !($this->validationErrors[] = 'invalid assertion subject');

        if (!$this->validateSignature($assertion)) return !($this->validationErrors[] = 'invalid assertion signature');

        return true;
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
