<?php

declare(strict_types=1);

namespace Chuck\Tests;

use PHPUnit\Framework\TestCase as BaseTestCase;

use Chuck\Config;
use Chuck\Request;
use Chuck\Router;

class TestCase extends BaseTestCase
{
    public readonly string $root;

    public function __construct(?string $name = null, array $data = [], $dataName = '')
    {
        parent::__construct($name, $data, $dataName);

        $this->root = realpath(
            __DIR__ . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR . 'fixtures'
        );
    }

    protected function setUp(): void
    {
        parent::setUp();

        $_SERVER['HTTP_HOST'] = 'www.example.com';
        $_SERVER['REQUEST_METHOD'] = 'GET';
        $_SERVER['REQUEST_URI'] = '/';
        $_SERVER['SERVER_PORT'] = '80';
        $_SERVER['SERVER_PROTOCOL'] = 'HTTP/1.1';
    }

    protected function tearDown(): void
    {
        unset($_SERVER['HTTPS']);
        unset($_SERVER['HTTP_HOST']);
        unset($_SERVER['REQUEST_METHOD']);
        unset($_SERVER['REQUEST_URI']);
        unset($_SERVER['SERVER_PORT']);
        unset($_SERVER['SERVER_PROTOCOL']);
    }

    public function setMethod(string $method): void
    {
        $_SERVER['REQUEST_METHOD'] = strtoupper($method);
    }

    public function setUrl(string $url): void
    {
        if (substr($url, 0, 1) === '/') {
            $_SERVER['REQUEST_URI'] = $url;
        } else {
            $_SERVER['REQUEST_URI'] = "/$url";
        }
    }

    public function setHost(string $host): void
    {
        $_SERVER['HTTP_HOST'] = $host;
    }

    public function enableHttps(): void
    {
        $_SERVER['HTTPS'] = 'on';
        $_SERVER['SERVER_PORT'] = '443';
    }

    public function disableHttps(): void
    {
        unset($_SERVER['HTTPS']);
        $_SERVER['SERVER_PORT'] = '80';
    }

    public function minimalOptions(): array
    {
        return [
            'path.root' => $this->root,
        ];
    }

    public function options(array $options = []): array
    {
        $ds = DIRECTORY_SEPARATOR;

        return array_merge(
            $this->minimalOptions(),
            [
                'appname' => 'chuck',
                'templates.default' => __DIR__ . "$ds..${ds}fixtures${ds}templates${ds}default",
            ],
            $options
        );
    }

    public function config(array $options = []): Config
    {
        return new Config($this->options($options));
    }


    public function request(
        ?string $method = null,
        ?string $url = null,
        ?bool $https = null,
        array $options = [],
    ): Request {
        if ($method) {
            $this->setMethod($method);
        }

        if ($url) {
            $this->setUrl($url);
        }

        if (is_bool($https)) {
            if ($https) {
                $this->enableHttps();
            } else {
                $this->disableHttps();
            }
        }

        $config = $this->config($options);
        $router = new Router();
        $request = new Request($config, $router);

        return $request;
    }
}
