SELECT
member,
<?php if ($interestedInNames ?? false) : ?>
    name,
<?php endif ?>
left,
joined
FROM members WHERE joined = :year
ORDER BY member;
