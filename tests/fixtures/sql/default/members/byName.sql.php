SELECT
member,
<?php if ($interestedInDates ?? false) : ?>
    joined,
    left,
<?php endif ?>
name
FROM members WHERE name = :name;
