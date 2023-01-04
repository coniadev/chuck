Chuck Framework
===============

Chuck is a lightweight and easily extendable PHP 8.1 web framework with focus 
on a simple architecture. 

> :warning: **Note**: This framework is under active development, some of the listed features are still experimental and subject to change. Large parts of the documentation are missing. 

It features:

* Routing
* A pure PHP template engine with auto escaping
* Database helpers (no ORM) with plain SQL migrations
* Form and JSON validaton
* Automatic image resizing
* Csrf protection
* Session and cookie helpers
* Custom middlewares
* Logging (PHP builtin logging or PSR-3 support)

## Usage:

### Installation:

    composer require conia/chuck

### Quick Start using the `App::create` helper:

```php
    use Conia\Chuck\{App, Config, Route, Request};

    $app = App::create(new Config('chuck'));
    $app->route('/', '\Namespace\Controller::index');
    $app->get('/user/{name}', (string $name) => "Hello, $name"));
    $app->post('/users', function (Request $request): Response {
        Users::create($request->json());

        return (new ResponseFactory())->json(['success' => true]);
    });
    $app->run();
```

### App initialization without helper:

```php
    use Conia\Chuck\{App, Config, Router, Route, Request, ResponseFactory};
    use Conia\Chuck\ErrorHandler;

    $config = new Config('chuck');

    $router = new Router();
    $router->add(Route::get('index', '/', function () {
        return ['data' => [1, 2, 3]];
    })->render('json'));
    $router->add(Route::get('file', '/file', function (Request $request) {
        return (new ResponseFactory())->file('/path/to/file.zip');
    }));

    // The ResponseFactory is optional
    $request = new Request($config, $router, new ResponseFactory())

    $errorHandler = new ErrorHandler($request);
    $errorHandler->setup();

    $app = new App($request);
    $app->run();
```

## License

Chuck is released under the MIT [license](LICENSE.md).

Copyright © 2022-2023 ebene fünf GmbH. All rights reserved.
