<?php

declare(strict_types=1);

namespace Chuck\Tests;

use PHPUnit\Framework\TestCase as BaseTestCase;

use Chuck\Testing\App;
use Chuck\Config;
use Chuck\Router;
use Chuck\Request;

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


    public function getRequest(array $options = []): Request
    {
        $config = $this->getConfig($options);
        $router = new Router();

        return new Request($config, $router);
    }

    public function getApp(array $options = []): App
    {
        $app = new App($this->getConfig($options));

        return $app;
    }
}
