<?php

declare(strict_types=1);

namespace Chuck\Testing;

use PHPUnit\Framework\TestCase as BaseTestCase;
use Chuck\Testing\App;
use Chuck\Config;
use Chuck\Router;

class TestCase extends BaseTestCase
{
    public static function setUpBeforeClass(): void
    {
    }

    public function getConfig(array $options = []): Config
    {
        $defaults = require __DIR__ . '/../defaults.php';

        return new Config(array_replace_recursive($defaults, $options));
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
