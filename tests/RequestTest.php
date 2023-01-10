<?php

declare(strict_types=1);

use Conia\Chuck\Exception\OutOfBoundsException;
use Conia\Chuck\Tests\Setup\TestCase;
use Nyholm\Psr7\Stream;
use Nyholm\Psr7\Uri;
use Psr\Http\Message\UploadedFileInterface;

uses(TestCase::class);


test('Helper methods', function () {
    $request = $this->request();

    expect($request->method())->toBe('GET');
    expect($request->isMethod('GET'))->toBe(true);
    expect($request->isMethod('POST'))->toBe(false);
});


test('Uri helpers', function () {
    $request = $this->request();

    expect($request->uri()->getPath())->toBe('/');
    expect((string)$request->uri())->toBe('http://www.example.com/');

    $this->setRequestUri('albums?from=1988&to=1991');
    $this->setQueryString('from=1988&to=1991');

    $request = $this->request();

    expect((string)$request->uri())->toBe('http://www.example.com/albums?from=1988&to=1991');
    expect($request->uri()->getHost())->toBe('www.example.com');
    expect($request->origin())->toBe('http://www.example.com');
});


test('Request::param', function () {
    $this->set('GET', ['chuck' => 'schuldiner', 'born' => '1967']);
    $request = $this->request();

    expect($request->param('chuck'))->toBe('schuldiner');
    expect($request->param('born'))->toBe('1967');
});


test('Request::param default', function () {
    $request = $this->request();

    expect($request->param('doesnotexist', 'the default'))->toBe('the default');
});


test('Request::param failing', function () {
    $request = $this->request();

    expect($request->param('doesnotexist'))->toBe(null);
})->throws(OutOfBoundsException::class, 'Query string');


test('Request::params', function () {
    $this->set('GET', ['chuck' => 'schuldiner', 'born' => '1967']);
    $request = $this->request();
    $params = $request->params();

    expect(count($params))->toBe(2);
    expect($params['born'])->toBe('1967');
    expect($params['chuck'])->toBe('schuldiner');
});


test('Request::field', function () {
    $this->setContentType('application/x-www-form-urlencoded');
    $this->setMethod('POST');
    $this->set('POST', ['chuck' => 'schuldiner', 'born' => '1967']);
    $request = $this->request();

    expect($request->field('chuck'))->toBe('schuldiner');
    expect($request->field('born'))->toBe('1967');
});


test('Request::field default $_POST is null', function () {
    $request = $this->request();

    expect($request->field('doesnotexist', 'the default'))->toBe('the default');
});


test('Request::field default $_POST is array', function () {
    $this->setContentType('application/x-www-form-urlencoded');
    $this->setMethod('POST');
    $this->set('POST', ['chuck' => 'schuldiner']);
    $request = $this->request();

    expect($request->field('doesnotexist', 'the default'))->toBe('the default');
});


test('Request::field failing', function () {
    $this->setContentType('application/x-www-form-urlencoded');
    $this->setMethod('POST');
    $request = $this->request();

    $request->field('doesnotexist');
})->throws(OutOfBoundsException::class, 'Form field');


test('Request::form', function () {
    $this->setContentType('application/x-www-form-urlencoded');
    $this->setMethod('POST');
    $this->set('POST', ['first_band' => 'Mantas', 'chuck' => 'schuldiner']);
    $request = $this->request();

    expect($request->form())->toBe([
        'first_band' => 'Mantas',
        'chuck' => 'schuldiner',
    ]);
});


test('Request::cookie', function () {
    $this->set('COOKIE', ['chuck' => 'schuldiner', 'born' => '1967']);
    $request = $this->request();

    expect($request->cookie('chuck'))->toBe('schuldiner');
    expect($request->cookie('born'))->toBe('1967');
});


test('Request::cookie default', function () {
    $request = $this->request();

    expect($request->cookie('doesnotexist', 'the default'))->toBe('the default');
});


test('Request::cookie failing', function () {
    $request = $this->request();

    $request->cookie('doesnotexist')->toBe(null);
})->throws(OutOfBoundsException::class, 'Cookie');


test('Request::cookies', function () {
    $this->set('COOKIE', ['chuck' => 'schuldiner', 'born' => '1967']);
    $request = $this->request();
    $cookies = $request->cookies();

    expect(count($cookies))->toBe(2);
    expect($cookies['born'])->toBe('1967');
    expect($cookies['chuck'])->toBe('schuldiner');
});


test('Request::server', function () {
    $request = $this->request();

    expect($request->server('HTTP_HOST'))->toBe('www.example.com');
    expect($request->server('SERVER_PROTOCOL'))->toBe('HTTP/1.1');
});


test('Request::server default', function () {
    $request = $this->request();

    expect($request->server('doesnotexist', 'the default'))->toBe('the default');
});


test('Request::server failing', function () {
    $request = $this->request();

    expect($request->server('doesnotexist'))->toBe(null);
})->throws(OutOfBoundsException::class, 'Server');


test('Request::servers', function () {
    $request = $this->request();
    $params = $request->serverParams();

    expect($params['HTTP_HOST'])->toBe('www.example.com');
    expect($params['SERVER_PROTOCOL'])->toBe('HTTP/1.1');
});


test('Request::attribute default', function () {
    $request = $this->request();

    expect($request->attribute('doesnotexist', 'the default'))->toBe('the default');
});


test('Request::attribute failing', function () {
    $request = $this->request();

    expect($request->attribute('doesnotexist'))->toBe(null);
})->throws(OutOfBoundsException::class, 'Request attribute');


test('Request attributes', function () {
    $request = $this->request();
    $request->withAttribute('one', 1)->withAttribute('two', '2');

    expect(count($request->attributes()))->toBe(2);
    expect($request->attribute('one'))->toBe(1);
    expect($request->attribute('two'))->toBe('2');
});


test('Request::body', function () {
    expect((string)$this->request()->body())->toBe('');
});


test('Request::json', function () {
    $stream = Stream::create('[{"title": "Leprosy", "released": 1988}, {"title": "Human", "released": 1991}]');
    $request = $this->request()->withBody($stream);

    expect($request->json())->toBe([
        ['title' => 'Leprosy', 'released' => 1988],
        ['title' => 'Human', 'released' => 1991],
    ]);
});


test('Request::json empty', function () {
    $request = $this->request();

    expect($request->json())->toBe(null);
});


test('Get file instance', function () {
    $this->setupFile();
    $request = $this->request();
    $file = $request->file('myfile');

    expect($file)->toBeInstanceOf(UploadedFileInterface::class);
});


test('Fail calling file without key', function () {
    $this->setupFile();
    $request = $this->request();
    $request->file();
})->throws(RuntimeException::class, 'No file key');


test('Get nested file instance', function () {
    $this->setupFile();
    $request = $this->request();
    $file = $request->file('nested', 'myfile');

    expect($file)->toBeInstanceOf(UploadedFileInterface::class);
});


test('Get all files', function () {
    $this->setupFiles(); // files array
    $request = $this->request();
    $files = $request->files();

    expect(count($files))->toBe(2);
    expect(isset($files['myfile']))->toBe(true);
    expect(isset($files['nested']))->toBe(true);
});


test('Get files instances', function () {
    $this->setupFiles(); // files array
    $request = $this->request();
    $files = $request->files('myfile');

    expect(count($files))->toBe(2);
    expect($files[0])->toBeInstanceOf(UploadedFileInterface::class);
    expect($files[1])->toBeInstanceOf(UploadedFileInterface::class);
});


test('Get nested files instances', function () {
    $this->setupFiles(); // files array
    $request = $this->request();
    $files = $request->files('nested', 'myfile');

    expect(count($files))->toBe(2);
    expect($files[0])->toBeInstanceOf(UploadedFileInterface::class);
    expect($files[1])->toBeInstanceOf(UploadedFileInterface::class);
});


test('Get nested files instances using an array', function () {
    $this->setupFiles(); // files array
    $request = $this->request();
    $files = $request->files(['nested', 'myfile']);

    expect(count($files))->toBe(2);
    expect($files[0])->toBeInstanceOf(UploadedFileInterface::class);
    expect($files[1])->toBeInstanceOf(UploadedFileInterface::class);
});


test('Get files instances with only one present', function () {
    $this->setupFile();
    $request = $this->request();
    $files = $request->files('myfile');

    expect(count($files))->toBe(1);
    expect($files[0])->toBeInstanceOf(UploadedFileInterface::class);
});


test('Access single file when mulitple are available', function () {
    $this->setupFiles();
    $request = $this->request();
    $request->file('myfile');
})->throws(RuntimeException::class, 'Multiple files');


test('File instance not available', function () {
    $request = $this->request();
    $request->file('does-not-exist');
})->throws(OutOfBoundsException::class, "Invalid file key ['does-not-exist']");


test('File instance not available (too much keys)', function () {
    $this->setupFile();
    $request = $this->request();
    $request->file('nested', 'myfile', 'toomuch');
})->throws(OutOfBoundsException::class, "Invalid file key (too deep) ['nested']['myfile']['toomuch']");


test('Access file using mulitple arrays', function () {
    $this->setupFiles();
    $request = $this->request();
    $request->files([], []);
})->throws(RuntimeException::class, 'Either provide');


test('Nested file instance not available', function () {
    $request = $this->request();
    $request->file('does-not-exist', 'really');
})->throws(OutOfBoundsException::class, "Invalid file key ['does-not-exist']['really']");


test('File instances are not available', function () {
    $request = $this->request();
    $request->files('does-not-exist');
})->throws(OutOfBoundsException::class, "Invalid files key ['does-not-exist']");


test('Nested file instances are not available', function () {
    $request = $this->request();
    $request->files('does-not-exist', 'really');
})->throws(OutOfBoundsException::class, "Invalid files key ['does-not-exist']['really']");


test('Getting and setting PSR-7 instance', function () {
    $psr7 = $this->psr7Request();
    $request = $this->request();
    $request->setPsr7($psr7);

    expect($request->psr7())->toBe($psr7);
});


test('PSR-7 message wrapper methods', function () {
    $request = $this->request()
        ->withProtocolVersion('2.0')
        ->withHeader('test-header', 'test-value')
        ->withHeader('test-header', 'test-value-replaced')
        ->withAddedHeader('test-header', 'test-value-added');

    $origBody = $request->getBody();
    $newBody = Stream::create('chuck');
    $request->withBody($newBody);

    expect((string)$origBody)->toBe('');
    expect((string)$newBody)->toBe('chuck');
    expect($request->getBody())->toBe($newBody);
    expect($request->getProtocolVersion())->toBe('2.0');
    expect(count($request->getHeaders()['test-header']))->toBe(2);
    expect($request->getHeaders()['test-header'][0])->toBe('test-value-replaced');
    expect($request->getHeaders()['test-header'][1])->toBe('test-value-added');
    expect($request->getHeader('test-header')[1])->toBe('test-value-added');
    expect($request->getHeaderLine('test-header'))->toBe('test-value-replaced, test-value-added');

    expect($request->hasHeader('test-header'))->toBe(true);
    $request->withoutHeader('test-header');
    expect($request->hasHeader('test-header'))->toBe(false);
});


test('PSR-7 server request wrapper methods', function () {
    $request = $this->request();
    $request->withMethod('PUT');
    $request->withRequestTarget('/chuck');
    $request->withQueryParams(['get' => 'get']);
    $request->withParsedBody(['post' => 'post']);
    $request->withCookieParams(['cookie' => 'cookie']);
    $request->withUri(new Uri('http://www.newexample.com'));
    $request->withAttribute('attribute', 'attribute');
    $request->withUploadedFiles([
        'myfile' => [
            'error' => UPLOAD_ERR_OK,
            'name' => '../malic/chuck-test-file.php',
            'size' => 123,
            'tmp_name' => __FILE__,
            'type' => 'text/plain',
        ],
    ]);

    expect($request->getServerParams()['SERVER_PROTOCOL'])->toBe('HTTP/1.1');
    expect($request->getMethod())->toBe('PUT');
    expect($request->getRequestTarget())->toBe('/chuck');
    expect($request->getQueryParams()['get'])->toBe('get');
    expect($request->getParsedBody()['post'])->toBe('post');
    expect($request->getCookieParams()['cookie'])->toBe('cookie');
    expect($request->getAttributes()['attribute'])->toBe('attribute');
    expect($request->getAttribute('attribute'))->toBe('attribute');
    expect(isset($request->getUploadedFiles()['myfile']))->toBe(true);

    $request->withoutAttribute('attribute');

    expect(isset($request->getAttributes()['attribute']))->toBe(false);
    expect($request->getAttribute('attribute', 'default'))->toBe('default');
});
