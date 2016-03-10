#!/usr/bin/perl

use strict;
use warnings;

my %type_map = (
    'fid' => 'FileId',
    'cid' => 'ContentId',
    'remote_cid' => 'ContentId',
    'dir' => 'const char *',
    'name' => 'const char *',
    'path' => 'const char *',
    'size' => 'ssize_t',
    'mtime' => 'time_t',
    'atime' => 'time_t',
    'checksum' => 'const char *',
    'remote_id' => 'const char *',
    'writable' => 'bool',
    'open_count' => 'int',
    'local' => 'bool',
     #'opened' => 'OpenState',
     'opened' => 'int',
    'downloading', => 'bool',
    'remote_path', => 'const char *',
    'blocked_by', => 'FileId'
);

my %no_type;

open F, "./sqlite3-pp < syncfs.cpp |";

my @array;
my @rest;

my $idx = 0;
while (<F>) {
    chomp;
    my $inline_bound = 0;
    s/^([A-Z]+) // or die;
    my $what = $1;
    if (s/^\$\=(\d+) //) {$inline_bound = $1;}
    my $query = $_;
    my $cols = <F>;
    chomp $cols;
    my @cols = split / /, $cols;
    die unless $cols[0] eq '@';
    shift @cols;
    @cols = () if grep {$_ eq '-'} @cols;    
    my $ib = $what eq 'SQL' ? $inline_bound : 0;
    push @array,"/* $idx */ SqlStmtInfo{\"$query\", NULL, $ib}";

    my $base = "SqlOther";
    if    ($query =~ /^select /i) {$base = "SqlSelect<>"}
    elsif ($query =~ /^insert /i) {$base = "SqlInsert"}

    my $res_t = "SqlResult";

    my @fields;
    if ($base eq 'SqlSelect<>' && @cols) {
	foreach my $col (@cols) {
	    my $typ;
	    if ($col =~ s/\`(.+)$//) {$typ = $1;}
	    else {$typ = $type_map{$col};}
	    if (defined $typ) {
		$typ = 'const char *' if $typ eq 'cstr';
		$typ = 'std::string'  if $typ eq 'string';
		push @fields, [$typ,$col];
	    } else {
		$no_type{$col}++;
		undef @fields;
		last;
	    }
	}
    }
    if (@fields > 0) {
	my $typ;
	my $str;
	if (@fields == 1) {
	    $typ = "SqL${idx}ResT";
	    $str = "typedef $fields[0][0] SqL${idx}ResT;\n";
	} else {
	    my $fields = join('', map {$_->[0].' '.$_->[1].'; '} @fields);
	    $typ = "SqL${idx}Cols";
	    $str = "struct $typ {$fields};\n";
	}
	$str .= "struct SqL${idx}Result : public SqlResult {\n";
	$str .= "  $typ res;\n";
	if (@fields == 1) {
	    $str .= "  void populate() {get(res); step_called = 1;}\n";
	} else {
	    $str .= "  void populate() {get(".join(',', map {"res.$_"} @cols)."); step_called = 1;}\n";
	}
	$str .= "  SqL${idx}Result() : SqlResult() {}\n";
	$str .= "  SqL${idx}Result(sqlite3 * db, sqlite3_stmt * stmt) : SqlResult(db, stmt) {}\n";
	$str .= "  SqL${idx}Result(SqL${idx}Result && other) : SqlResult(std::move(other)) {}\n";
	$str .= "  SqL${idx}Result & operator=(SqL${idx}Result && other) {SqlResult::operator=(std::move(other)); return *this;}\n";
	$str .= "  using SqlResult::get;\n";
	$str .= "  const $typ & get() {if (step_called == 0) step(); if (step_called == 2) populate(); return res;}\n";
	$str .= "  const $typ & operator*() {if (step_called == 0) step(); if (step_called == 2) populate(); return res;}\n";
	if (@fields > 1) {
	    $str .= "  const $typ * operator->() {if (step_called == 0) step(); if (step_called == 2) populate(); return &res;}\n";
	}
	$str .= "  typedef $typ Value;\n";
	$str .= "  typedef SqLIter<SqL${idx}Result> Iterator;\n";
	$str .= "  Iterator begin() {return Iterator(this);}\n";
	$str .= "  Iterator end() {return Iterator(NULL);}\n";
	#if (true) {
	#    $str .= "  std::vector<Value> get_all() {std::vector<Value> ret; while(step()) {populate(); ret.push_back(std::move(res));} return ret;}\n";
	#}
	$str .= "};\n";
	push @rest, $str;
	$res_t = "SqL${idx}Result";
	$base = "SqlSelect<SqL${idx}Result>";
    }

    
    my $tparms = join(', ', map {"typename T$_"} (1..$inline_bound));
    my $tline = $tparms ? "template <$tparms>" : '';
    my $parms = join(', ', map {"T$_ arg$_"} (1..$inline_bound));
    my $args = join(', ', map {"arg$_"} (1..$inline_bound));

    if ($what eq 'EXEC') {
	my $ret_t = $base eq 'SqlInsert' ? 'int64_t' : 'void';
	my $ret = $ret_t eq 'void' ? '' : 'return';
	my $str = "$tline static inline $ret_t SqL$idx($parms) {$ret $base(&SqL_queries[$idx]).exec1($args);}\n";
	push @rest, $str;
    } elsif ($what eq 'SELECT') {
	my $str = "$tline static inline $res_t SqL$idx($parms) {return $base(&SqL_queries[$idx])($args);}\n";
	push @rest, $str;
    } elsif ($inline_bound == 0) {
	push @rest, "struct SqL$idx : public $base {SqL$idx() : $base(&SqL_queries[$idx]) {}};\n";
    } else {
	my $bind = join('', map {" bind(idx, arg$_);"} (1..$inline_bound));
	my $str = "struct SqL$idx : public $base\n";
	$str .= "  {$tline SqL$idx($parms) : $base(&SqL_queries[$idx]) {prepare(); int idx = 1; $bind}";
	$str .= "};\n";
	push @rest, $str;
    }
    $idx++;
}

open O, ">queries-gen.hpp\n";

print O <<'---';
#include <array>
---

print O "std::array<SqlStmtInfo,$idx> SqL_queries{{\n";
print O "  ";
print O join(",\n  ", @array);
print O "\n}};\n";
foreach (@rest) {
    print O $_;
}

open F, "syncfs.sql";

print O "\n";
print O "const char * SqL_schema = \n";
while (<F>) {
    chomp;
    s/"/\\"/g;
    print O  qq'  "$_\\n"\n';
}
print O ";\n";

#foreach (sort keys %no_type) {
#    print STDERR ">$_<\n";
#}
