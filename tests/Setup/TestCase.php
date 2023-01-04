<?php

declare(strict_types=1);

namespace Conia\Chuck\Tests\Setup;

use Conia\Chuck\App;
use Conia\Chuck\Config;
use Conia\Chuck\Exception\ValueError;
use Conia\Chuck\Logger;
use Conia\Chuck\Registry\Registry;
use Conia\Chuck\Request;
use Conia\Chuck\Routing\Router;
use PHPUnit\Framework\TestCase as BaseTestCase;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Log\LoggerInterface;

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
        unset($_SERVER['HTTP_HOST']);
        unset($_SERVER['REQUEST_METHOD']);
        unset($_SERVER['REQUEST_URI']);
        unset($_SERVER['SERVER_PROTOCOL']);
        unset($_SERVER['argv']);

        // HTTPS values
        unset($_SERVER['HTTPS']);
        unset($_SERVER['HTTP_X_FORWARDED_PROTO']);
        unset($_SERVER['REQUEST_SCHEME']);

        global $_GET;
        $_GET = [];
        global $_POST;
        $_POST = [];
        global $_FILES;
        $_FILES = [];
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

    public function setRequestUri(string $url): void
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

    public function enableHttps(?string $serverKey = null): void
    {
        if ($serverKey) {
            $_SERVER[$serverKey] = 'https';
        } else {
            $_SERVER['HTTPS'] = 'on';
        }
    }

    public function disableHttps(): void
    {
        unset($_SERVER['HTTPS']);
        unset($_SERVER['REQUEST_SCHEME']);
        unset($_SERVER['HTTP_X_FORWARDED_PROTO']);
    }

    public function config(bool $debug = false): Config
    {
        $config = new Config('chuck', debug: $debug);
        $config->setupLogger(function (): LoggerInterface {
            return new Logger();
        });

        return $config;
    }

    public function app(Config $config = null): App
    {
        return App::create($config ?? $this->config());
    }

    public function registry(
        ?Request $request = null,
        ?Config $config = null,
    ): Registry {
        $registry = new Registry();
        $request = $request ?: $this->request();
        $config = $config ?: $this->config();

        $registry->add(Request::class, $request);
        $registry->add($request::class, $request);
        $registry->add(Config::class, $config);
        $registry->add($config::class, $config);

        return $registry;
    }

    public function psr7Request(): ServerRequestInterface
    {
        $psr17Factory = new \Nyholm\Psr7\Factory\Psr17Factory();

        $creator = new \Nyholm\Psr7Server\ServerRequestCreator(
            $psr17Factory, // ServerRequestFactory
            $psr17Factory, // UriFactory
            $psr17Factory, // UploadedFileFactory
            $psr17Factory  // StreamFactory
        );

        return $creator->fromGlobals();
    }

    public function request(
        ?string $method = null,
        ?string $url = null,
        ?bool $https = null,
    ): Request {
        if ($method) {
            $this->setMethod($method);
        }

        if ($url) {
            $this->setRequestUri($url);
        }

        if (is_bool($https)) {
            if ($https) {
                $this->enableHttps();
            } else {
                $this->disableHttps();
            }
        }

        $request = new Request($this->psr7Request());

        return $request;
    }

    public function setupFile()
    {
        global $_FILES;

        $_FILES = [
            'myfile' => [
                'error'    => UPLOAD_ERR_OK,
                'name'     => '../malic/chuck-test-file.php',
                'size'     => 123,
                'tmp_name' => __FILE__,
                'type'     => 'text/plain'
            ],
            'failingfile' => [
                'error'    => UPLOAD_ERR_PARTIAL,
                'name'     => 'chuck-failing-test-file.php',
                'size'     => 123,
                'tmp_name' => '',
                'type'     => 'text/plain'
            ]
        ];
    }

    public function setupFiles()
    {
        global $_FILES;

        $_FILES = [
            'myfile' => [
                'error'    => [UPLOAD_ERR_OK, UPLOAD_ERR_PARTIAL],
                'name'     => ['test.php', 'test2.php'],
                'size'     => [123, 234],
                'tmp_name' => [__FILE__, __FILE__],
                'type'     => ['text/plain', 'text/plain']
            ]
        ];
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
