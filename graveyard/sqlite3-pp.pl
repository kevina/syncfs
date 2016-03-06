use strict;
use warnings;

$/ = undef;
$_  = <STDIN>;

pos $_ = 0;

sub handle_ws();
sub handle_sql();

my $last_pos = 0;

sub flush() {
    my $new_pos = pos $_;
    print substr($_, $last_pos, $new_pos-$last_pos);
    $last_pos = $new_pos;
}
sub skip() {
    $last_pos = pos $_;
}

while (pos $_ < length $_) {
    next if handle_ws();
    next if /\G(: "(\\.|[^"])*" # double quoted string
                | '(\\.|[^'])*' # single quoted string
               )/sgcx;
    my $pos = pos $_;
    if (m/\G([a-zA-Z_]+)/gc) {
	if ($1 eq 'SQL') {
	    pos $_ = $pos;
	    #pos $_ = $pos;
	    print STDERR ">1>",pos $_,"\n";
	    handle_sql();
	    print STDERR ">2>",pos $_,"\n";
	} else {
	    #print STDERR "??$1\n";
	}
    } else {
	pos $_ = (pos $_) + 1;
    }
}
flush();

sub handle_ws() {
    return m~\G(: /\*.*?\*/  # c comments
                | //[^\n]*   # c++ comments
                | \#[^\n]*   # preprocessor directives
                | [ \n]+     # white space
            )~sgcx ? 1 : 0;
}

my $idx = 0;
my @queries;

sub handle_sql() {
    $idx++;
    flush();
    my $start = pos $_;
    die unless /\GSQL/gc;
    handle_ws();
    die unless /\G\(/gc;
    handle_ws();
    my $str = '';
    while (/\G"(\\.|[^"])*"/gc) {
	$str .= $1;
	$str .= ' ';
	handle_ws();
    }
    my $stop = pos $_;
    skip();
    my $r = substr($_, $start, $stop - $start);
    $r =~ tr/\n/ /c;
    my $idx_str = "SqL$idx(";
    my $repl = substr($r, 0, length($idx_str));
    $repl =~ tr/\n//cd;
    my $rest = substr($r, length($idx_str));
    print $idx_str,$repl,$rest;
    die unless /\G\)/gc;
}

foreach (@queries) {
    next unless /^[ \n]*select[ \n]/ig;
    while (accept_column($_)) {
    }    
}
