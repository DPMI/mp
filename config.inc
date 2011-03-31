<?php
//Database configuration
//CONFIGURATION FILE// Edit with care

$DB_SERVER="localhost";
$DATABASE='marc';
$user='marc';
$password='konko';
$path='uploadedfiles/';

$max_size=1000000;
$Connect = mysql_connect($DB_SERVER, $user, $password) or die ("Cant connect to MySQL at $DB_SERVER");
mysql_select_db($DATABASE,$Connect) or die ("Cant connect to $DATABASE database");

$sql_update="SELECT * FROM guiconfig WHERE selected=1";
$result=mysql_query($sql_update);
if(!$result) {
        print "MySQL error: " . mysql_error();
        exit;
}
if(mysql_num_rows($result)>0) {
        $row = mysql_fetch_array($result);
} else { // PRoblems. Use some default

}
$pageStyle=$row["pageStyle"];
$pageStyleBad=$row["pageStyleBad"];
$projectName=$row["projectName"];
$selectedID=$row["id"];
?>
