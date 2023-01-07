<?php

declare(strict_types=1);

use Conia\Chuck\Request;
use Conia\Chuck\Response;
use Conia\Chuck\Tests\Fixtures\TestAttribute;

if (!function_exists('_testJsonRendererIterator')) {
    function _testJsonRendererIterator()
    {
        $arr = [13, 31, 73];
        foreach ($arr as $a) {
            yield $a;
        }
    }
}

if (!function_exists('_testFunctionMiddleware')) {
    function _testFunctionMiddleware(Request $request, callable $next): Response
    {
        $response = $next($request);

        return $response->body('first' . (string)$response->getBody());
    }
}

if (!function_exists('_testViewWithAttribute')) {
    #[TestAttribute]
    function _testViewWithAttribute(string $name): string
    {
        return $name;
    }
}
