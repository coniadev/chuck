Chuck Framework
===============

[![Software License](https://img.shields.io/badge/license-MIT-brightgreen.svg)](LICENSE.md)
[![Coverage Status](https://img.shields.io/scrutinizer/coverage/g/coniadev/chuck.svg)](https://scrutinizer-ci.com/g/coniadev/chuck/code-structure)
[![Psalm coverage](https://shepherd.dev/github/coniadev/chuck/coverage.svg?)](https://shepherd.dev/github/coniadev/chuck)
[![Psalm level](https://shepherd.dev/github/coniadev/chuck/level.svg?)](https://conia.dev/chuck)
[![Quality Score](https://img.shields.io/scrutinizer/g/coniadev/chuck.svg)](https://scrutinizer-ci.com/g/coniadev/chuck)

Chuck is a lightweight and easily extendable PHP 8.1 web framework. 

> :warning: **Note**: This framework is under active development, some of the listed features are still experimental and subject to change. Parts of the documentation are missing or wrong. 

It features:

* Routing
* Csrf protection
* An autowiring container
* Session and cookie helpers
* Custom and PSR-15 middleware 
* Logging (PHP builtin logging or PSR-3 support)

Supported PSRs:

* PSR-3 Logger Interface
* PSR-4 Autoloading
* PSR-7 Http Messages (Request, Response, Stream)
* PSR-11 Container Interface
* PSR-12 Extended Coding Style
* PSR-15 Http Middleware

## Usage:

### Installation:

    composer require nyholm/psr7 nyholm/psr7-server conia/chuck

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

## License

Chuck is released under the MIT [license](LICENSE.md).

Copyright © 2022-2023 ebene fünf GmbH. All rights reserved.
