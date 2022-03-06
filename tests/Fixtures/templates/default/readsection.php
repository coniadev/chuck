<div><?= $this->body() ?><?= $this->text ?></div>
<?php if ($this->hasSection('list')) : ?>
    <?php echo $this->section('list'); ?>
<?php else : ?>
    <p>no list</p>
<?php endif ?>
