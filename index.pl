#!/usr/bin/perl 
#	require "error.pm"; 
	use CGI qw/:standard/; 
	use POSIX qw(strftime);	
	use Net::Traceroute;
	use Net::DNS; 
	use Net::Telnet;
	use Socket;
	
#	use strict;
	use warnings;
#	open(STDOUT, '>', 'dw.log') or die "Can't open log";
	open(STDERR, '>', "/www/perl/dw.log") or die "Can't open log";

	
	my $query = new CGI;
	my $url   = $query->url;
	my $domain = $query->param("domain");
	my @todo = $query->param('todo');

	print header;
	print start_html(-title=>'WhoisPage',
			-encoding => 'utf-8',
			-head=>Link({-rel => 'shortcut icon', -type => 'image/x-icon', -href =>'http://static.be5.ru/images/favicon.ico'}),
	                -style=>{'src'=>'http://static.be5.ru/css/basic.css'});
	print "<h1> Whois Page</h1>\n";

	print_prompt();
	do_work();
	print_tail();
	print end_html;

	sub print_prompt {
	   print start_form;
	   print "<em>Domain: </em> ";
	   print textfield(-name=>'domain',
                           -size=>50, 
			   -maxlength=>255);

	   print "<p><em>Options: </em> ";
	   print checkbox_group(
				 -name=>'todo',
				 -values=>[host,whois,mx,mtr],
				 -defaults=>[whois,host]);

	   print "<p>",submit;
	   print reset;
	   print end_form;
	   print "<hr>";
	}

#==========do_work=============================
	sub do_work {
# paneslas ispolnyatsya	
	

	 if (param('domain')) { 
		print "<h4>Output: </h4>";
	
		foreach my $values (@todo) {
			if ($values eq 'host') { name2ip($domain); }
   			if ($values eq 'whois') { whois_function($domain); } 
		#	if ($values eq 'host') { host_function($domain); }	
			if ($values eq 'mtr') { mtr_function($domain); }
			#print "<hr>";
		}


	} 
	else { print "<h6>NO INPUT TEXT</h6>"; } 		

	print "<br>";

	}

#==========print tail=============================
	sub print_tail {
		$cur_year = strftime "%Y", gmtime;   
	print "<br><hr><p>",$cur_year,"(c)</p>"; 
	}


#=========whois_function==============================
	# primaet argument text - vozvrat -> rezultat systemnogo whois
	sub whois_function {
		print "<fieldset style=\"width: 50%\">";
		print "<legend><h5>Whois section</h5></legend>";	
		my $domain = shift; 
		
		if ($domain =~ m/^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[-a-zA-Z0-9]{2,8}$/) { 
#		print "<em>$domain</em>";
		
		my $whois_server = "whois.tcinet.ru"; 
		my ($telnet, @t_output);
		$telnet = new Net::Telnet; 
		$telnet->open(Host => $whois_server, 
			 Port => 43,
			 Timeout => 5);
		$telnet->print($domain."\r\n");
		@t_output = $telnet->getlines; 
## if <string> ~= <ip regex>... ; else ...
## regexp for domain(like abc.com): ^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$		
## regexp for ip: ((^|\.)((25[0-5])|(2[0-4]\d)|(1\d\d)|([1-9]?\d))){4}$ 


		unless  ( $domain ) { die; }  
			else  { 
                        
                        foreach my $line (@t_output) {
                      #  print $line,"<br>";
			if($line=~/state|status:\s*([a-z]+)/i){
 			 print "$line<br>";
				}
			if($line=~/person:\s*([a-z0-9:_]+)/i){
                         print "$line<br>";
				}
			if($line=~/nserver:\s*([a-z0-9:_]+)/i){
                         print "<em>$line</em><br>";
                                }
			if($line=~/org:\s*([a-z0-9:_]+)/i){
                         print "$line<br>";
                                }
			if($line=~/registrar:\s*([a-z]+)/i){
                         print "$line<br>";
                                }
			if($line=~/admin-contact:\s*([a-z0-9:_]+)/i){
                         print "$line<br>";
                                }
			if($line=~/created:\s*([a-z0-9]+)/i){
                         print "$line<br>";
                                }
			if($line=~/paid-till:\s*([a-z0-9]+)/i){
                         print "$line<br>";
                                }
			if($line=~/free-date:\s*([a-z0-9]+)/i){
                         print "$line<br>";
                                }
			if($line=~/source:\s*([a-z0-9]+)/i){
                         print "$line<br> ";
                                }
			}	
		} 
		
		}  elsif ($domain =~ m/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/)  {
			use Net::Whois::IP qw(whoisip_query);
			whois_ip($domain); 	
			
			} else  { print "<b>undefined</b>"; }
  

		print "</fieldset>";
		return; 
	} 
	
#=========whois_ip_function==============================

	sub whois_ip {
        	my $addr = shift;
		#my $addr = ; 
#        	my $response = whoisip_query($addr);
#        	foreach (sort keys(%{$response}) ) {
#         		print "$response->{$_} <br>";
        	my $response = whoisip_query( $addr,"true");
		        foreach ( sort keys %$response ){
               		print "<b>$_ :</b><br>";
                		foreach ( @{ $response->{ $_ } } )
                        		{ print " $_ <br>"; }
                }


  	return ;
	}


#=========mtr_function==============================
	sub mtr_function {
		print "<fieldset style=\"width: 50%\">";
		print "<legend><h5>Traceroute section</h5></legend>";
		my $domain = shift;
		my $mtr = "/usr/sbin/mtr --report $domain -c10 --no-dns -o LSD";
		
		if (my @result =`$mtr`) { 
			print "<p>Command: /usr/sbin/mtr --report ".$domain." --no-dns -c10 -o LSD </p>";
                	print "<pre>"; 
			foreach my $line (@result) {
                        print $line;
                	}
			print "</pre>";
		} else { print "Failed due executing command with input value <em>".$domain."</em>"; }
		print "</fieldset>";
	return;
	}


#=========ip2name_function==============================
	sub ip2name {
		use Socket;
		my $iaddr = inet_aton($_[0]);
		if (my $ptr = gethostbyaddr($iaddr, AF_INET)) {
 		print  $_[0]." has <b>".$ptr."</b>";
		}
		else { print "No PTR or invalid value for ".$_[0]; }
	return;
	}
 
#=========name2ip_function==============================	
	sub name2ip {
		print "<fieldset style=\"width: 50%\">";
		print "<legend><h5>Check IP & PTR for domain section</h5></legend>";
		my $domain = $_[0];
		use Net::hostent;
		if ($hent = gethostbyname($domain)) {
		    $name      = $hent->name;           
		    $addr_ref  = $hent->addr_list;
		    @addresses = map { inet_ntoa($_) } @$addr_ref;
		}
		print "<table border=0><tr><td><b>IP address<b></td><td><b>PTR record </b></td><td><b>MX record</b></td><tr><td>";
		foreach my $value (@addresses) { 		
			print $value."<br>";
			} 
		print "<p><br></td> <td>";
		foreach my $value1 (@addresses) {
			print ip2name($value1)."<br> ";
			}
		print "</td><td>";
		check_mx($domain);
		print "</p></td></tr></table></fieldset>";
		return; 
	}

#=========check_mx_function==============================

	sub check_mx {
		my ($host, @mx);  
		my $domain = shift;
		my $res = Net::DNS::Resolver->new( );
		if (@mx = mx($res, $domain)) {	
			print "<p>";
			foreach my $record (@mx) {
	                print $record->preference." ".$record->exchange."<br>";
			}
			print "</p>";
		} 
		
  		else { print "<p>No MX records. </p>"; } 
		
		return; 
	}



#=========dig_function==============================

