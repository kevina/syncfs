#!/usr/bin/perl

use strict;
use warnings;

open F, "./sqlite3-pp < syncfs.cpp |";

my @array;
my @rest;

my $idx = 0;
while (<F>) {
    chomp;
    my $query = $_;
    my $cols = <F>;
    push @array,"SqlStmtInfo{\"$query\", NULL}";
    if ($query =~ /^select /) {
	push @rest, "struct SqL$idx : public SqlSelect {SqL$idx() : SqlSelect(&SqL_queries[$idx]) {}};\n";
    } 
    $idx++;
}

close F;
open O, ">queries-gen.hpp\n";

print O "#include <array>\n";
print O "std::array<SqlStmtInfo,$idx> SqL_queries{{\n";
print O "  ";
print O join(",\n  ", @array);
print O "\n}};\n";
print O "struct SqL : public SqlStmt {SqL(int i) : SqlStmt(&SqL_queries[i]) {}};\n";
print O "\n";
foreach (@rest) {
    print O $_;
}
