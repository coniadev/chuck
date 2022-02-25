<?php

declare(strict_types=1);

use Chuck\Tests\TestCase;
use Chuck\Routing\Router;
use Chuck\Log;

uses(TestCase::class);


test('Log to file', function () {
    // capture output of error_log calls in a temporary file
    // to prevent it printed to the console.
    $default = ini_set('error_log', stream_get_meta_data(tmpfile())['uri']);
    $tmpfile = tmpfile();
    $logfile = stream_get_meta_data($tmpfile)['uri'];

    $logger = new Log($this->request(options: ['path.logfile' => $logfile]));

    $logger->debug("Scott");
    $logger->info("Steve");
    $logger->notice("James");
    $logger->warning("Chuck");
    $logger->error("Bobby");
    $logger->critical("Chris");
    $logger->alert("Kelly");
    $logger->emergency("Terry");

    $output = file_get_contents($logfile);

    expect($output)->toContain('] DEBUG: Scott');
    expect($output)->toContain('] INFO: Steve');
    expect($output)->toContain('] NOTICE: James');
    expect($output)->toContain('] WARNING: Chuck');
    expect($output)->toContain('] ERROR: Bobby');
    expect($output)->toContain('] CRITICAL: Chris');
    expect($output)->toContain('] ALERT: Kelly');
    expect($output)->toContain('] EMERGENCY: Terry');

    ini_set('error_log', $default);
});


test('Log to php sapi', function () {
    $tmpfile = tmpfile();
    $logfile = stream_get_meta_data($tmpfile)['uri'];
    $default = ini_set('error_log', $logfile);

    $logger = new Log($this->request());

    $logger->debug("Scott");
    $logger->info("Steve");
    $logger->warning("Chuck");
    $logger->error("Bobby");
    $logger->alert("Kelly");

    $output = file_get_contents($logfile);

    expect($output)->toContain('] DEBUG: Scott');
    expect($output)->toContain('] INFO: Steve');
    expect($output)->toContain('] WARNING: Chuck');
    expect($output)->toContain('] ERROR: Bobby');
    expect($output)->toContain('] ALERT: Kelly');

    ini_set('error_log', $default);
});


test('Log with higher debug level', function () {
    $tmpfile = tmpfile();
    $logfile = stream_get_meta_data($tmpfile)['uri'];
    $default = ini_set('error_log', $logfile);

    $logger = new Log($this->request(options: ['loglevel' => Log::ERROR]));

    $logger->debug("Scott");
    $logger->info("Steve");
    $logger->notice("James");
    $logger->warning("Chuck");
    $logger->error("Bobby");
    $logger->critical("Chris");
    $logger->alert("Kelly");
    $logger->emergency("Terry");

    $output = file_get_contents($logfile);

    expect($output)->not->toContain('] DEBUG: Scott');
    expect($output)->not->toContain('] INFO: Steve');
    expect($output)->not->toContain('] NOTICE: James');
    expect($output)->not->toContain('] WARNING: Chuck');
    expect($output)->toContain('] ERROR: Bobby');
    expect($output)->toContain('] CRITICAL: Chris');
    expect($output)->toContain('] ALERT: Kelly');
    expect($output)->toContain('] EMERGENCY: Terry');

    ini_set('error_log', $default);
});


test('Message interpolation', function () {
    $tmpfile = tmpfile();
    $logfile = stream_get_meta_data($tmpfile)['uri'];
    $default = ini_set('error_log', $logfile);

    $logger = new Log($this->request());

    try {
        throw new \Exception('The test exception');
    } catch (\Exception $e) {
        $logger->warning(
            'String: {string}, Integer: {integer} ' .
                'DateTime: {datetime}, Array: {array}' .
                'Float: {float}, Object: {object} ' .
                'Other: {other}, Null: {null}',
            [
                'string' => 'Scream Bloody Gore',
                'integer' => 13,
                'float' => 73.23,
                'datetime' => new \DateTime('1987-05-25T13:31:23'),
                'array' => [13, 23, 71],
                'object' => new Router(),
                'other' => stream_context_create(),
                'null' => null,
                'exception' => $e,
            ]
        );
    }

    $output = file_get_contents($logfile);

    expect($output)->toContain('String: Scream Bloody Gore');
    expect($output)->toContain('Integer: 13');
    expect($output)->toContain('Float: 73.23');
    expect($output)->toContain('DateTime: 1987-05-25 13:31:23');
    expect($output)->toContain('Array: [Array [13,23,71]]');
    expect($output)->toContain('Object: [Instance of Chuck\Routing\Router]');
    expect($output)->toContain('Other: [resource]');
    expect($output)->toContain('Null: [null]');
    expect($output)->toContain('Exception Message: The test exception');

    ini_set('error_log', $default);
});
