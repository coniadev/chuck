<?php

declare(strict_types=1);

namespace Chuck;

use Chuck\Exception\HttpNotFound;
use \Hashids\Hashids;

class Hash
{
    public function __construct(RequestInterface $request)
    {
        $this->request = $request;
        $config = $request->config;
        $this->config = $config;
        $secret = $config->get('hashsecret');

        if ($secret) {
            $this->hashids = new Hashids($secret, 8);
        } else {
            $this->hashids = new Hashids('', 8);
        }
    }

    public function encode(int $id): string
    {
        return $this->hashids->encode($id);
    }

    public function decode(string $id): int
    {
        try {
            // error_log($id . " " . print_r($this->hashids->decode($id)[0], true));
            return $this->hashids->decode($id)[0];
        } catch (\Exception) {
            // Hashes are used exclusively for addressing resources in
            // external requests. If a hash is incorrect, someone may
            // have tried to tamper with it.
            throw new HttpNotFound($this->request);
        }
    }
}
