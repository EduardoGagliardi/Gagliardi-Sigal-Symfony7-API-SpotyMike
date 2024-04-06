<?php
// Start the session
session_start();
?>
<!DOCTYPE html>
<html>

<body>
    cd
    <?php
// Set session variables
try {
    //code...
    echo "Session: ".$_SESSION["favcolor"];
} catch (\Throwable $th) {
    echo "Session: out";
    //throw $th;
}
?>

</body>

</html>