#!/usr/bin/perl

# (C) Maxim Dounin

# Tests for nginx realip module.

###############################################################################

use warnings;
use strict;

use Test::More;

use Socket qw/ CRLF /;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http realip rewrite/);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    add_header X-IP $remote_addr;
    set_real_ip_from  127.0.0.1/32;
    set_real_ip_from  10.0.1.0/24;

    map $http_x_forwarded_for $real_ip_src {
        ""       $proxy_protocol_addr;
        default  "$http_x_forwarded_for,$proxy_protocol_addr";
    }

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location / { }
        location /custom {
            real_ip_header    X-Real-IP-Custom;
        }

        location /1 {
            real_ip_header    X-Forwarded-For;
            real_ip_recursive off;
        }

        location /2 {
            real_ip_header    X-Forwarded-For;
            real_ip_recursive on;
        }

        location /var {
            real_ip_header    $http_x_custom_real_ip;
        }

        location /var-arg {
            real_ip_header    $arg_ip;
        }

        location /var-mixed {
            real_ip_header    192.0.2.$arg_octet;
        }

        location /var-rec-off {
            real_ip_header    $http_x_custom_xff;
            real_ip_recursive off;
        }

        location /var-rec-on {
            real_ip_header    $http_x_custom_xff;
            real_ip_recursive on;
        }
    }

    server {
        listen       127.0.0.1:8081;
        server_name  localhost;

        return 204;
    }

    server {
        listen       127.0.0.1:8082 proxy_protocol;
        server_name  localhost;

        set_real_ip_from  127.0.0.1/32;
        set_real_ip_from  192.0.2.9/32;
        real_ip_header    $real_ip_src;
        real_ip_recursive on;

        location / { }
    }

    server {
        listen       127.0.0.1:8083 proxy_protocol;
        server_name  localhost;

        set_real_ip_from  10.0.0.1/32;
        real_ip_header    $real_ip_src;
        real_ip_recursive on;

        location / { }
    }
}

EOF

$t->write_file('index.html', '');
$t->write_file('custom', '');
$t->write_file('1', '');
$t->write_file('2', '');
$t->write_file('var', '');
$t->write_file('var-arg', '');
$t->write_file('var-mixed', '');
$t->write_file('var-rec-off', '');
$t->write_file('var-rec-on', '');
$t->run();

plan(skip_all => 'no 127.0.0.1 on host')
	if http_get('/') !~ /X-IP: 127.0.0.1/m;

$t->plan(19);

###############################################################################

like(http(<<EOF), qr/^X-IP: 192.0.2.1/m, 'realip');
GET / HTTP/1.0
Host: localhost
X-Real-IP: 192.0.2.1

EOF

like(http(<<EOF), qr/^X-IP: 192.0.2.1/m, 'realip custom');
GET /custom HTTP/1.0
Host: localhost
X-Real-IP-Custom: 192.0.2.1

EOF

like(http_xff('/1', '10.0.0.1, 192.0.2.1'), qr/^X-IP: 192.0.2.1/m,
	'realip multi');
like(http_xff('/1', '192.0.2.1, 10.0.1.1, 127.0.0.1'),
	qr/^X-IP: 127.0.0.1/m, 'realip recursive off');
like(http_xff('/2', '10.0.1.1, 192.0.2.1, 127.0.0.1'),
	qr/^X-IP: 192.0.2.1/m, 'realip recursive on');

like(http(<<EOF), qr/^X-IP: 10.0.1.1/m, 'realip multi xff recursive off');
GET /1 HTTP/1.0
Host: localhost
X-Forwarded-For: 192.0.2.1
X-Forwarded-For: 127.0.0.1, 10.0.1.1

EOF

like(http(<<EOF), qr/^X-IP: 192.0.2.1/m, 'realip multi xff recursive on');
GET /2 HTTP/1.0
Host: localhost
X-Forwarded-For: 10.0.1.1
X-Forwarded-For: 192.0.2.1
X-Forwarded-For: 127.0.0.1

EOF

my $s = IO::Socket::INET->new('127.0.0.1:' . port(8081));
like(http(<<EOF, socket => $s), qr/ 204 .*192.0.2.1/s, 'realip post read');
GET / HTTP/1.0
Host: localhost
X-Real-IP: 192.0.2.1

EOF

# variables in real_ip_header

like(http(<<EOF), qr/^X-IP: 192.0.2.1/m, 'realip var http');
GET /var HTTP/1.0
Host: localhost
X-Custom-Real-IP: 192.0.2.1

EOF

like(http(<<EOF), qr/^X-IP: 127.0.0.1/m, 'realip var http empty');
GET /var HTTP/1.0
Host: localhost

EOF

like(http_get('/var-arg?ip=192.0.2.1'), qr/^X-IP: 192.0.2.1/m,
	'realip var arg');
like(http_get('/var-arg'), qr/^X-IP: 127.0.0.1/m, 'realip var arg empty');
like(http_get('/var-arg?ip=not-an-ip'), qr/^X-IP: 127.0.0.1/m,
	'realip var arg invalid');
like(http_get('/var-mixed?octet=42'), qr/^X-IP: 192.0.2.42/m,
	'realip var mixed');

like(http(<<EOF), qr/^X-IP: 127.0.0.1/m, 'realip var recursive off');
GET /var-rec-off HTTP/1.0
Host: localhost
X-Custom-Xff: 192.0.2.1, 10.0.1.1, 127.0.0.1

EOF

like(http(<<EOF), qr/^X-IP: 192.0.2.1/m, 'realip var recursive on');
GET /var-rec-on HTTP/1.0
Host: localhost
X-Custom-Xff: 10.0.1.1, 192.0.2.1, 127.0.0.1

EOF

# combine incoming header with $proxy_protocol_addr in one directive

my $pp = 'PROXY TCP4 192.0.2.9 192.0.2.2 123 5678' . CRLF;

like(pp_get(8082, $pp, '192.0.2.1'), qr/^X-IP: 192.0.2.1/m,
	'realip var pp trusted with xff');
like(pp_get(8082, $pp), qr/^X-IP: 192.0.2.9/m,
	'realip var pp trusted no xff');
like(pp_get(8083, $pp, '192.0.2.1'), qr/^X-IP: 127.0.0.1/m,
	'realip var pp untrusted');

###############################################################################

sub http_xff {
	my ($uri, $xff) = @_;
	return http(<<EOF);
GET $uri HTTP/1.0
Host: localhost
X-Forwarded-For: $xff

EOF
}

sub pp_get {
	my ($p, $proxy, $xff) = @_;
	my $s = IO::Socket::INET->new('127.0.0.1:' . port($p));
	my $req = "GET / HTTP/1.0" . CRLF . "Host: localhost" . CRLF;
	$req .= "X-Forwarded-For: $xff" . CRLF if defined $xff;
	$req .= CRLF;
	return http($proxy . $req, socket => $s);
}

###############################################################################
