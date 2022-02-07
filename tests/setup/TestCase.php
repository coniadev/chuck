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
    public static function setUpBeforeClass(): void
    {
    }

    public function getConfig(array $options = []): Config
    {
        $ds = DIRECTORY_SEPARATOR;
        $defaults = require __DIR__ . '/../../src/defaults.php';

        return new Config(array_replace_recursive($defaults, [
            'path' => [
                'root' => __DIR__ . $ds . '..' . $ds . '..',
            ]
        ], $options));
    }


    public function request(
        array $options = [],
        string $method = null,
        string $url = null,
    ): Request {
        $config = $this->getConfig($options);
        $router = new Router();
        $request = new Request($config, $router);

        if ($method) {
            $request->setMethod(strtoupper($method));
        }

        if ($url) {
            $request->setUrl($url);
        }

        return $request;
    }

    public function getApp(
        array $options = [],
        string $method = null,
        string $url = null,
    ): App {
        $app = new App($this->request($options, $method, $url));

        return $app;
    }
}
