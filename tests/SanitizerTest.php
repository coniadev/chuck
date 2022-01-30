<?php

declare(strict_types=1);

use Chuck\Util;

const MALFORMED = '
        <header>Test</header>
        <aside><div>Test</div></aside>
        <iframe src="example.com"></iframe>
        <nav><ul><li>Test</li></ul></nav>
        <article>
            <script>console.log("hans");</script>
            <section>
                <h1 onclick="console.log("hans");">Test</h1>
            </section>
        </article>
        <footer>Test</footer>';


test('default extensions', function () {
    $util = new Util($this->getRequest());


    $clean = '
        Test
        <div>Test</div>
        <ul><li>Test</li></ul>
                <h1>Test</h1>
        Test';

    expect($util->clean(MALFORMED))->toBe($clean);
});

test('block extension', function () {
    $util = new Util($this->getRequest([
        'sanitizer' => [
            'extensions' => [
                'basic',
                'block',
            ],
        ]
    ]));

    $clean = '
        Test
        <aside><div>Test</div></aside>
        Test
        <article>
            <section>
                <h1>Test</h1>
            </section>
        </article>
        Test';

    expect($util->clean(MALFORMED))->toBe($clean);
});

test('headfoot extension', function () {
    $util = new Util($this->getRequest([
        'sanitizer' => [
            'extensions' => [
                'basic',
                'headfoot',
            ],
        ]
    ]));

    $clean = '
        <header>Test</header>
        <div>Test</div>
        Test
                <h1>Test</h1>
        <footer>Test</footer>';

    expect($util->clean(MALFORMED))->toBe($clean);
});

test('nav extension', function () {
    $util = new Util($this->getRequest([
        'sanitizer' => [
            'extensions' => [
                'basic',
                'list',
                'nav',
            ],
        ]
    ]));

    $clean = '
        Test
        <div>Test</div>
        <nav><ul><li>Test</li></ul></nav>
                <h1>Test</h1>
        Test';

    expect($util->clean(MALFORMED))->toBe($clean);
});
