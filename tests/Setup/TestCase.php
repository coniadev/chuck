<?php

declare(strict_types=1);

namespace Conia\Chuck\Tests\Setup;

use Conia\Chuck\App;
use Conia\Chuck\Config;
use Conia\Chuck\Exception\ValueError;
use Conia\Chuck\Logger;
use Conia\Chuck\Psr\Factory;
use Conia\Chuck\Registry;
use Conia\Chuck\Request;
use Conia\Chuck\Router;
use Nyholm\Psr7\Factory\Psr17Factory;
use PHPUnit\Framework\TestCase as BaseTestCase;
use Psr\Http\Message\ResponseInterface as PsrResponse;
use Psr\Http\Message\ServerRequestInterface as PsrServerRequest;
use Psr\Log\LoggerInterface as PsrLogger;

/**
 * @internal
 *
 * @coversNothing
 */
class TestCase extends BaseTestCase
{
    public function __construct(?string $name = null, array $data = [], $dataName = '')
    {
        parent::__construct($name, $data, $dataName);
    }

    protected function setUp(): void
    {
        parent::setUp();

        $_SERVER['HTTP_ACCEPT'] = 'text/html,application/xhtml+xml,text/plain';
        $_SERVER['HTTP_ACCEPT_ENCODING'] = 'gzip, deflate, br';
        $_SERVER['HTTP_ACCEPT_LANGUAGE'] = 'en-US,de;q=0.7,en;q=0.3';
        $_SERVER['HTTP_HOST'] = 'www.example.com';
        $_SERVER['HTTP_USER_AGENT'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:108.0) ' .
            'Gecko/20100101 Firefox/108.0';
        $_SERVER['REQUEST_METHOD'] = 'GET';
        $_SERVER['REQUEST_URI'] = '/';
        $_SERVER['SERVER_PROTOCOL'] = 'HTTP/1.1';
    }

    protected function tearDown(): void
    {
        unset(
            $_SERVER['CONTENT_TYPE'],
            $_SERVER['HTTPS'],
            $_SERVER['HTTP_ACCEPT'],
            $_SERVER['HTTP_ACCEPT_ENCODING'],
            $_SERVER['HTTP_ACCEPT_LANGUAGE'],
            $_SERVER['HTTP_HOST'],
            $_SERVER['HTTP_USER_AGENT'],
            $_SERVER['HTTP_X_FORWARDED_PROTO'],
            $_SERVER['QUERY_STRING'],
            $_SERVER['REQUEST_METHOD'],
            $_SERVER['REQUEST_SCHEME'],
            $_SERVER['REQUEST_URI'],
            $_SERVER['SERVER_PROTOCOL'],
            $_SERVER['argv'],
        );

        global $_GET;
        $_GET = [];
        global $_POST;
        $_POST = [];
        global $_FILES;
        $_FILES = [];
        global $_COOKIE;
        $_COOKIE = [];
    }

    public function set(string $method, array $values): void
    {
        global $_GET;
        global $_POST;
        global $_COOKIE;

        foreach ($values as $key => $value) {
            if (strtoupper($method) === 'GET') {
                $_GET[$key] = $value;

                continue;
            }
            if (strtoupper($method) === 'POST') {
                $_POST[$key] = $value;

                continue;
            }
            if (strtoupper($method) === 'COOKIE') {
                $_COOKIE[$key] = $value;
            } else {
                throw new ValueError("Invalid method '{$method}'");
            }
        }
    }

    public function setMethod(string $method): void
    {
        $_SERVER['REQUEST_METHOD'] = strtoupper($method);
    }

    public function setContentType(string $contentType): void
    {
        $_SERVER['HTTP_CONTENT_TYPE'] = $contentType;
    }

    public function setRequestUri(string $url): void
    {
        if (substr($url, 0, 1) === '/') {
            $_SERVER['REQUEST_URI'] = $url;
        } else {
            $_SERVER['REQUEST_URI'] = "/{$url}";
        }
    }

    public function setQueryString(string $qs): void
    {
        $_SERVER['QUERY_STRING'] = $qs;
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
        unset($_SERVER['HTTPS'], $_SERVER['REQUEST_SCHEME'], $_SERVER['HTTP_X_FORWARDED_PROTO']);
    }

    public function config(bool $debug = false): Config
    {
        return new Config('chuck', debug: $debug);
    }

    public function app(Config $config = null): App
    {
        return App::create($config ?? $this->config());
    }

    public function registry(
        ?Request $request = null,
        ?Config $config = null,
        bool $autowire = true,
    ): Registry {
        $registry = new Registry(autowire: $autowire);
        $config = $config ?: $this->config();

        App::initializeRegistry($registry, $config, new Router());

        $request = $request ?: $this->request();
        $registry->add(Request::class, $request);
        $registry->add($request::class, $request);

        $registry->add(PsrLogger::class, function (): PsrLogger {
            return new Logger();
        });

        return $registry;
    }

    public function factory(): Factory
    {
        return $this->registry()->get(Factory::class);
    }

    public function psrRequest(): PsrServerRequest
    {
        $factory = new Psr17Factory();

        $creator = new \Nyholm\Psr7Server\ServerRequestCreator(
            $factory, // ServerRequestFactory
            $factory, // UriFactory
            $factory, // UploadedFileFactory
            $factory  // StreamFactory
        );

        return $creator->fromGlobals();
    }

    public function psrResponse(): PsrResponse
    {
        $factory = new Psr17Factory();

        return $factory->createResponse();
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

        return new Request($this->psrRequest());
    }

    public function setupFile()
    {
        global $_FILES;

        $_FILES = [
            'myfile' => [
                'error' => UPLOAD_ERR_OK,
                'name' => '../malic/chuck-test-file.php',
                'size' => 123,
                'tmp_name' => __FILE__,
                'type' => 'text/plain',
            ],
            'failingfile' => [
                'error' => UPLOAD_ERR_PARTIAL,
                'name' => 'chuck-failing-test-file.php',
                'size' => 123,
                'tmp_name' => '',
                'type' => 'text/plain',
            ],
            'nested' => [
                'myfile' => [
                    'error' => UPLOAD_ERR_OK,
                    'name' => '../malic/chuck-test-file.php',
                    'size' => 123,
                    'tmp_name' => __FILE__,
                    'type' => 'text/plain',
                ],
            ],
        ];
    }

    public function setupFiles()
    {
        global $_FILES;

        $_FILES = [
            'myfile' => [
                'error' => [UPLOAD_ERR_OK, UPLOAD_ERR_PARTIAL],
                'name' => ['test.php', 'test2.php'],
                'size' => [123, 234],
                'tmp_name' => [__FILE__, __FILE__],
                'type' => ['text/plain', 'text/plain'],
            ],
            'nested' => [
                'myfile' => [
                    'error' => [UPLOAD_ERR_OK, UPLOAD_ERR_PARTIAL],
                    'name' => ['test.php', 'test2.php'],
                    'size' => [123, 234],
                    'tmp_name' => [__FILE__, __FILE__],
                    'type' => ['text/plain', 'text/plain'],
                ],
            ],
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
