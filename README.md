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
    use Chuck\{App, Config, Route, Request};

    $app = App::create(new Config('chuck'));
    $app->route('/', '\Namespace\Controller::index');
    $app->get('/user/{name}', (string $name) => "Hello, $name"));
    $app->post('/users', function (Request $request): Response {
        Users::create($request->json());

        return $request->response()->json(['success' => true]);
    });
    $app->run();
```

### App initialization without helper:

```php
    use Chuck\{App, Config, Router, Route, Request, ResponseFactory};
    use Chuck\Error\Handler;

    $config = new Config('chuck');

    $router = new Router();
    $router->add(Route::get('index', '/', function () {
        return ['data' => [1, 2, 3]];
    })->render('json'));
    $router->add(Route::get('file', '/file', function (Request $request) {
        return $request->response->file('/path/to/file.zip');
    }));

    // The ResponseFactory is optional
    $request = new Request($config, $router, new ResponseFactory())

    $errorHandler = new Handler($request);
    $errorHandler->setup();

    $app = new App($request);
    $app->run();
```

## Documentation

* [Routing](docs/routing.md)
* [Request](docs/request.md)
* [Response](docs/response.md)
* [Templates](docs/templates.md)
* [Validation](docs/validation.md)
* [File Uploads](docs/fileuploads.md)
* [Sessions and Cookies](docs/sessionscookies.md)
* [Middleware](docs/middleware.md)
* [Renderers](docs/renderers.md)
* [Database/SQL](docs/database.md)
* [Migrations](docs/migrations.md)
* [Images/Assets](docs/assets.md)
* [Logging](docs/logging.md)
* [Command Line Interface](docs/cli.md)
* [Contributing](docs/contributing.md)


## License

Chuck is released under the MIT [license](LICENSE.md).

Copyright © 2022 ebene fünf GmbH. All rights reserved.
