<?
require("config.inc");

$port=2000;
$IP='127.0.0.1';

function ntohl($port) {
  $b=pack("N", $port);
  return $b;
}



print "Lets talk tell the client.<br>\n";
//$IP=$_POST["ip"];
//$port=$_POST["port"];

$type=8;//$_POST["type"];
$message='konkelbar';//$_POST["message"];

$message=ntohl($type) . sprintf("%s",$message);	


//$message=sprintf("%c%s",$type,$message);

print "Contacting ctrl $IP:$port <h1>$message</h1>\n";
$fp = fsockopen("udp://$IP", $port, $errno, $errstr);
if (!$fp) {
   echo "ERROR: $errno - $errstr<br />\n";
} else {
   fwrite($fp, $message);
   fclose($fp);
}





?>
</body></html>