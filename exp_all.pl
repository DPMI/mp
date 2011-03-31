
#!/usr/bin/perl

use IO::Socket;
use Sys::Hostname;

#Fetch basic system informartion
$server_port=1579;

$host_name=hostname();
$pid=$$;
$serv="$host_name:$server_port($pid)";
$host_IP=gethostbyname($host_name) or die "Couldn't resolve $host_name: $! ";
$hostname = gethostbyaddr($host_IP,AF_INET) or die "Couldn't re-resolve $host_name: $!";

$host_IP=inet_ntoa($host_IP);
@args=@ARGV;

print "Starting server on $host_name($host_IP) port $server_port \n";

$server = IO::Socket::INET->new(LocalPort	=> 	$server_port,
			Type 		=>	SOCK_STREAM,
			Reuse		=>	1,
			Listen		=>	10 )
	or die "TG: Couldn�t be a TCP server on port $server_port: $@ \n";
#Flush output.
$server->autoflush();
print "TG:Server started.\n";
$traceindex=1;

$noDenys=0;
#Main loop, waits for clients to connect. 
#Once connected, the client enters the internal CLIENT: loop.
#The client can terminate its own connection by sending bye, and doing a close(SOCKET);
#It can also terminate the server by sending a shutdown.
SERVER: while (($client,$client_address) = $server->accept()) {
	($port,$iaddr)=sockaddr_in($client_address);	#Find out clients IP and name
#	$client_ip=inet_ntoa($iaddr);			# Possible to fool
#	$client_name=gethostbyaddr($iaddr,AF_INET);	# Solution, do a reverse lookup.
	print "CONNECTED " . Timestamp() ."\n";
	

      CLIENT:while($msg = <$client>) {
	  print "GOT: $msg --";
	  chomp($msg);
	  if($msg=~/\bBYE\b/) {
	      print "TG: Got bye\n";
	      print $client "SERVER TERMINATING CONNECTION TO CLIENT.\n";
	      last CLIENT;
	  } elsif($msg=~/\bSHUTDOWN\b/) {
	      print "TG: Got shutdown\n";
	      print $client "SERVER SHUTTING DOWN!\n";
	      last SERVER;
	  } elsif($msg=~/SERVER/) {
	      @args=split(/:/,$msg);
	      $expid=$args[1];
	      $runid=$args[2];
	      $keyid=$args[3];
	      # Check if expid directory exists.. if not make it.
	      
	      if ( -d "$expid" ) {
		  print "Expid dir exists.";
	      } else {
		  mkdir "$expid", 0777 unless -d "$expid";
	      }
	      
	      $execstr=sprintf("./udpServer1 -e %s -r %s -k %s",$expid,$runid,$keyid);
	      print "->$execstr \n";
	      open PS, "$execstr|";
	      $response="CRAP";
	      while($myIn=<PS>){
		  print "$myIn \n";
		  if($myIn=~/>output_file/){
		      $response="$myIn";
		  }
	      }
	      print "Server done\n";
	      close PS;
	      print $client "GOT: $response";
	  } elsif($msg=~/CLIENT/ ){
	      @args=split(/:/,$msg);
	      $expid=$args[1];
	      $runid=$args[2];
	      $keyid=$args[3];
	      $server=$args[4];
	      $port=$args[5];
	      $pkts=$args[6];
	      $pktLen=$args[7];
	      $waittime=$args[8];
	      if ( -d "expid")
	      {
		  print "Expid dir exist";
	      }else {
		  mkdir "$expid", 0777 unless -d "$expid";
	      }
	      #executing Cleint
	      $execstr=sprintf("./udpClient1 -e %s -r %s -k %s -s %s -p %s -n %s -l %s -w %s",$expid,$runid,$keyid,$server,$port,$pkts,$pktLen,$waittime); 
	      print "->$execstr|";
	      open PS, "$execstr|";
	      $response="CRAP";
	      while($myIn=<PS>){
		  if($myIn=~/output_file/){
		      $response="$myIn";
		  }
		  
	      }
	      print $client "Client done. $myIn\n";
	  }elsif($msg=~/MP/){
	      #execute flush MP
	      system('/usr/bin/php flushMp.php');
	      sleep(5);
	      system('/usr/bin/php killMP.php');
	      sleep(5);
	      #copy trace.cap 

	      system('/usr/bin/killall mp');
	      #adapt config file....
	      @args=split(/:/,$msg);
	      $direction=$args[1];
	      print "cp trace0.cap /data/mujo09/TCP/trace_$traceindex.cap \n";
	      system("cp trace0.cap /data/mujo09/TCP/trace_$traceindex.cap");
	      $traceindex++;
	     # if($direction==0){
		#  system('cp mp.conf_1 mp.conf');
	     # } 
	     # if($direction==1){
		#  system('cp mp.conf_1 mp.conf');
	     # } 
	      if($direction==2){
		  system('cp mp.conf_both mp.conf');
	      } 
	      #start runme_rako.sh
	      sleep(10);
	      system('./mp &');
	      print $client "MP Done\n";
	  } else {
	      #Give the client some response
	      print $client "Your : $msg doesnt mean a thing to me.OK?\n";
	      print "TG:GOT WIERD MESSAGE FROM CLIENT: $msg\n";
	      
	  }
	  
	  print "TG: DISCONNECTED: $client_name($client_ip).\n";
	  
      }
	close($server);	
	exit;
    }


sub Timestamp {
    my ($sec,$min, $hour, $mday, $mon,$year,$wday,$yday,$isdst);
    ($sec,$min, $hour, $mday, $mon,$year,$wday,$yday,$isdst)=localtime(time);
    $year+=1900;
    $mon+=1;
    return "$year $mon $mday $hour:$min:$sec ";
}

sub phoenix {
    # close all your connections, kill children and
    # prepare to be reincarnated 
    exec($self,@args);
}

sub read_config {
    do $CONFIG_FILE1;
    
}         

