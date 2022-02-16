<?php

declare(strict_types=1);

namespace Chuck\Tests;

use PHPUnit\Framework\TestCase as BaseTestCase;

use Chuck\Testing\App;
use Chuck\Testing\Request;
use Chuck\Config;
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

    public static function setUpBeforeClass(): void
    {
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
        array $options = [],
    ): Request {
        $config = $this->config($options);
        $router = new Router();
        $request = new Request($config, $router);

        if ($method) {
            $request->setMethod(strtoupper($method));
        }

        if ($url !== null) {
            $request->setUrl($url);
        }

        return $request;
    }

    public function getApp(
        array $options = [],
        ?string $method = null,
        ?string $url = null,
    ): App {
        $app = new App($this->request($method, $url, $options));

        return $app;
    }

    public function enableHttps(): void
    {
        $_SERVER['HTTPS'] = 'on';
    }

    public function disableHttps(): void
    {
        unset($_SERVER['HTTPS']);
    }
}
