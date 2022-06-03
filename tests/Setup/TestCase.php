<?php

declare(strict_types=1);

namespace Chuck\Tests\Setup;

use PHPUnit\Framework\TestCase as BaseTestCase;
use Psr\Log\LoggerInterface;

use \ValueError;
use Chuck\App;
use Chuck\Config;
use Chuck\ConfigInterface;
use Chuck\Logger;
use Chuck\Registry;
use Chuck\RegistryInterface;
use Chuck\Request;
use Chuck\Routing\Router;
use Chuck\Routing\RouterInterface;


class TestCase extends BaseTestCase
{
    public function __construct(?string $name = null, array $data = [], $dataName = '')
    {
        parent::__construct($name, $data, $dataName);
    }

    protected function setUp(): void
    {
        parent::setUp();

        $_SERVER['HTTP_HOST'] = 'www.example.com';
        $_SERVER['REQUEST_METHOD'] = 'GET';
        $_SERVER['REQUEST_URI'] = '/';
        $_SERVER['SERVER_PROTOCOL'] = 'HTTP/1.1';
    }

    protected function tearDown(): void
    {
        unset($_SERVER['HTTPS']);
        unset($_SERVER['HTTP_HOST']);
        unset($_SERVER['REQUEST_METHOD']);
        unset($_SERVER['REQUEST_URI']);
        unset($_SERVER['SERVER_PROTOCOL']);
        unset($_SERVER['argv']);
        global $_GET;
        $_GET = [];
        global $_POST;
        $_POST = [];
    }

    public function set(string $method, array $values): void
    {
        global $_GET;
        global $_POST;

        foreach ($values as $key => $value) {
            if (strtoupper($method) === 'GET') {
                $_GET[$key] = $value;
                continue;
            }
            if (strtoupper($method) === 'POST') {
                $_POST[$key] = $value;
            } else {
                throw new ValueError("Invalid method '$method'");
            }
        }
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
    }

    public function disableHttps(): void
    {
        unset($_SERVER['HTTPS']);
    }

    public function minimalOptions(): array
    {
        return [
            'app' => 'chuck',
            'path.root' => C::root(),
        ];
    }

    public function options(array $options = []): array
    {
        return array_merge(
            $this->minimalOptions(),
            [
                'templates' => C::root() . C::DS . 'templates' . C::DS . 'default',
            ],
            $options
        );
    }

    public function config(array $options = []): Config
    {
        return new Config($this->options($options));
    }

    public function app(array $options = []): App
    {
        return App::create($this->config($options));
    }


    public function request(
        ?string $method = null,
        ?string $url = null,
        ?bool $https = null,
        array $options = [],
        ?RouterInterface $router = null,
        ?ConfigInterface $config = null,
        ?RegistryInterface $registry = null,
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

        if ($config === null) {
            $config = $this->config($options);
            $config->setupLogger(function (): LoggerInterface {
                return new Logger();
            });
        }

        if ($router === null) {
            $router = new Router();
        }

        if ($registry === null) {
            $registry = new Registry();
        }

        $request = new Request($config, $router, $registry);

        return $request;
    }

    public function fullTrim(string $text): string
    {
        return trim(
            preg_replace(
                '/> </',
                '><',
                preg_replace(
                    '/\s+/',
                    ' ',
                    preg_replace('/\n/', '', $text)
                )
            )
        );
    }
}
