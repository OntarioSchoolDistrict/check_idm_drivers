#!/usr/bin/perl -w

# Original code from https://www.perlmonks.org/?node_id=227766
# Modified to extract IDM Driver Status, by David Benjamin, 2023
#

use strict;
use Getopt::Long;
use Net::LDAP;

my ($host,$user,$port,$pass,$base,$debug,$state);

my $result = GetOptions('H=s'=>\$host,
                        'p=s'=>\$port,
                        'D=s'=>\$user,
                        'w=s'=>\$pass,
                        'b=s'=>\$base,
                        'v+'=>\$debug,
                        'u'=>\&usage
                       );

my %ERRORS=('OK'=>0,'WARNING'=>1,'CRITICAL'=>2,'UNKNOWN'=>3,'DEPENDENT'=>4);

# Set some options if necessary and carp
# if no user/pass was supplied
unless($user && $pass){ &usage; }
unless($base){ &usage; }
unless($host){ $host = 'yourserver.yourdomain.com'; }
unless($port){ $port = '389'; }
unless($debug){ $debug = 0; }

if($debug){ print "\n\nTesting TLS...\n\n"; }
testtls();

sub testtls {

   if($debug){
      print "H: [$host]\n
             p: [$port]\n
             D: [$user]\n
             w: [$pass]\n
             b: [$base]\n
             v: [$debug]\n
            ";
   }

   # Make an LDAP Object
   my $ldap=new Net::LDAP($host,
                          port=>$port,
                          version=>3,
                          debug=>$debug,
                          ) || die "ldap failed";
   if ($debug){ print "New Net::LDAP object created successfully\
+n"; }

   # Start TLS
   my $mesg=$ldap->start_tls(verify=>'none',
                             sslversion=>'sslv2/3',
                             ) || die "start tls failed: $!\n";
   my $code= $mesg->code;
   if($debug){ print "TLS Status: ",$mesg->error,"\n"; }
   unless($mesg->code == 0){ print "CODE: ",$mesg->code,"\n"; die; }

   # Bind with dn and password
   $mesg = $ldap->bind(dn=>$user,
                       password=>$pass,
                      ) || die "bind failed: $!\n";
   $code = $mesg->code;
   if($debug){ print "Bind Status: ",$mesg->error,"\n\n"; }

   # Get driver attributes
   my $srch = $ldap->search(
                            base => $base,
                            scope => 'base',
                            timelimit => 30,
                            filter => 'objectclass=*',
                            attrs => ['driver-state']
                        );

   unless($srch->code == 0){
        $ldap->unbind;
        print "UNKNOWN: ",$srch->error,"\n\n";
        exit $ERRORS{'UNKNOWN'};
    }

   $state = $srch->entry->get_value( 'driver-state' );

   $ldap->unbind;

   if($debug){ print "driver-state: ",$state,"\n\n" };

   if ( $state =~ /stopped/i ){
       print "CRITICAL: $base is $state\n\n";
       exit $ERRORS{'CRITICAL'};
   }

   if ( $state =~ /running/i ){
      print "OK: $base is $state\n\n";
      exit $ERRORS{'OK'};
   } 

}


# options similar to searchldap command.
# openldap2-2.4.46
# http://www.openldap.org

sub usage{
   print "\n\n";
   print "check_idm_drivers.pl -H [host] -p [port] -D [DN] -w [passwd] -b [DN] -d [debu
+g]\n";
   print "\n\n";
   print "[host] is the fully qualified domain name or ip address of the ldap server\n";
   print "   ldapserver\.domain\.tld  ||  192.168.1.100\n";
   print "\n";
   print "[port] is the port over which tls communication takes places (usually 389)\n";
   print "\n";
   print "[DN] is the distinguished name of a valid user in LDAP:\n";
   print "   \"cn=Alan Smithee,dc=orgunit,dc=com\"\n";
   print "NOTE:  user must have access to the server attibute \"NDSRightsToMonitor\"\n";
   print "    see the eDirectory Administration Guide, Monitoring section.\n";
   print "\n";
   print "[password] is the LDAP password associated with the valid user's dn\n";
   print "   \'133tpasswd!\'\n";
   print "\n";
   print "[DN] is the distinguished base name of a valid IDM driver in LDAP:\n";
   print "   \"cn=driver1,ou=drivers,o=system\"\n";
   print "\n";
   print "[debug] is set for debugging information (default is 0 - success/fail info only)\n";
   print "\n\n";

   exit;
}
