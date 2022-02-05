<?php

declare(strict_types=1);

namespace Chuck\Testing;

use Chuck\Testing\Request;
use Chuck\App as BaseApp;

class App extends BaseApp
{
    public function getTestRequest(): Request
    {
        return $this->request;
    }

    public function buildRequest(string $url = null, $method = 'get', $body = null, $json = null, $csrf = true): Request
    {
        $request = $this->getTestRequest();

        if ($url) {
            $request->setUrl($url);
        }

        $request->setMethod($method);

        if ($body) {
            if ($csrf) {
                $body['csrftoken'] =  $request->session->csrf->get();
            }
            $request->setBody($body);
        }

        if ($json) {
            $request->setJson($json);
        }

        return $request;
    }
}
