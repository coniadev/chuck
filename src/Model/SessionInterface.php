<?php

declare(strict_types=1);

namespace Chuck\Model;

interface SessionInterface
{
    public function open($savepath, $id);
    public function read($id);
    public function write($id, $data);
    public function destroy($id);
    public function close();
    public function gc($max);
}
