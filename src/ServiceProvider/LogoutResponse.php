<?php

namespace Smindel\SAML\ServiceProvider;

class LogoutResponse extends Response
{
    public function validate($requestID = null, $issuer = null)
    {
        $xpath = new \DOMXPath($this->ownerDocument);

        if (!$this->validateSchema()) return !($this->validationErrors[] = 'invalid schema');

        if (!$this->validateSignature()) return !($this->validationErrors[] = 'invalid response signature');

        if ($requestID && $this['@InResponseTo'] != $requestID) return !($this->validationErrors[] = 'invalid request id');

        if (!$this->validateStatus()) return !($this->validationErrors[] = 'invalid status');

        if (!$this->validateIssuer($issuer)) return !($this->validationErrors[] = 'invalid issuer');

        return true;
    }
}
