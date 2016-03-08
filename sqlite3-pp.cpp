#include <string.h>
#include <assert.h>

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

using namespace std;

static inline bool asc_isspace(unsigned char c) 
{
  return c==' ' || c=='\n' || c=='\r' || c=='\t' || c=='\f' || c=='\v';
}
static inline bool asc_isdigit(unsigned char c)
{
  return '0' <= c && c <= '9';
}
static inline bool asc_isalpha(unsigned char c)
{
  return ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z') || c == '_';
}

struct SubStr {
  char * begin;
  char * end;
  size_t size() const {return end-begin;}
  explicit operator bool() const {return begin != end;}
};

ostream & operator << (ostream & o, SubStr str) {
  o << string(str.begin,str.end);
  return o;
}

static inline bool operator==(SubStr x, const char * y) {
  return strncmp(x.begin,y,x.size()) == 0 && y[x.size()] == '\0';
}

static inline bool eq_icase(const string & x, const char * y) {
  return strcasecmp(x.c_str(), y) == 0;
}

struct Main {
  int main() {
    char * data;
    char * end;
    {
      // FIXME: Use a better method that doesn't involve unnecessary copying
      std::stringstream buffer;
      buffer << cin.rdbuf();
      auto file = buffer.str();
      // for convince make sure the string has _two_ null characters
      file += '\0';
      file += '\0';
      data = (char *)malloc(file.size());
      memcpy(data, file.data(), file.size());
      end = data + file.size();
    }
    char * p = data;
    while (p < end) {
      p = skip_whitespace(p);
      if (*p == '"') {
	p = get_quote(p, '"').end;
      } else if (*p == '\'') {
	p = get_quote(p, '\'').end;
      } else if (asc_isalpha(*p)) {
	auto id = get_id(p);
	if (id == "SQL") {
	  p = handle_sql(p, "SQL");
	} else if (id == "EXEC") {
	  p = handle_sql(p, "EXEC");
	} else if (id == "SELECT") {
	  p = handle_sql(p, "SELECT");
	} else {
	  p = id.end;
	}
      } else {
	++p;
      }
    }
    ofstream("syncfs-gen.cpp") 
      << "#line 1 \"syncfs.cpp\"\n"
      << data;
    return 0;
  }

  char * skip_whitespace(char * p) {
  again:
    if (asc_isspace(*p)) {++p; goto again;}
    if (p[0] == '/' && p[1] == '/') {p += 2; while (*p && *p != '\n') ++p; goto again;}
    if (p[0] == '/' && p[1] == '*') {p += 2; while (*p && !(p[0] == '*' && p[1] == '/')) ++p; goto again;}
    if (p[0] == '#') {p += 1; while (*p && *p != '\n') ++p; goto again;}
    return p;
  }

  SubStr get_quote(char * p, char q) {
    char * begin = p;
    ++p;
    while (*p && p[0] != q) {
      if (p[0] == '\\') p += 2;
      else p += 1;
    }
    expect(p, q);
    ++p;
    return {begin, p};
  }

  SubStr get_id(char * p) {
    char * begin = p;
    while (asc_isalpha(*p) || asc_isdigit(*p)) ++p;
    return {begin, p};
  }

  char * handle_sql(char * p, const char * what) {
    vector<SubStr> parts;
    char * begin = p;
    p += strlen(what);
    p = skip_whitespace(p);
    expect(p, '(');
    ++p;
    p = skip_whitespace(p);
    size_t query_len = 0;
    while (*p && *p != ')') {
      expect(p, '"');
      auto res = get_quote(p, '"');
      p = res.end;
      res.begin++;
      res.end--;
      query_len += res.size();
      parts.push_back(res);
      p = skip_whitespace(p);
    }
    expect(p, ')');
    ++p;
    char * end = p;
    proc_sql({begin, end}, std::move(parts), query_len, what);
    return p;
  }

  void expect(char * p, char c) {
    // FIXME: Proper error message
    assert(*p == c);
  }

  void proc_sql(SubStr, vector<SubStr>&&, size_t, const char * what);
};

int sql_num = 0;

struct ProcSql {
  SubStr orig_text;
  vector<SubStr> parts;
  vector<SubStr>::iterator itr;
  char *                   p;
  string query;
  int splice_count;
  struct Column {
    string name;
    string type;
    bool last;
  };
  vector<Column> columns;
  const char * what;

  ProcSql(SubStr orig, vector<SubStr> && pts, size_t sz, const char * w) 
    : orig_text(orig), parts(std::move(pts)), splice_count(0), what(w)
  {
    itr = parts.begin();
    p = itr->begin;
    query.reserve(sz);
  }
  void main() {
    clear_orig();
    string id;
    try_id(id);
    bool what_eq_select = strcmp(what, "SELECT")==0;
    bool id_eq_select = eq_icase(id, "select");
    if (what_eq_select || id_eq_select) {
      if (id_eq_select) get_id(id);
      else query += "select ";
      proc_select();
      proc_rest();
    } else {
      get_id(id);
      proc_rest();
    }
    cout << what << " ";
    if (splice_count > 0) 
      cout << "$=" << splice_count << ' ';
    cout << query << "\n";
    cout << "@ ";
    for (auto & col : columns) {
      if (col.name.empty())
	cout << "-";
      else
	cout << col.name;
      if (!col.type.empty())
	cout << '`' << col.type;
      cout << ' ';
    }
    cout << "\n";
    p = orig_text.begin;
    char buf[16];
    auto res = snprintf(buf, 16, "SqL%d(", sql_num++);
    //int newlines = 0
    for (int i = 0; i < res; ++i) {
      assert(asc_isspace(p[i]));
      //if (p[i] == '\n') newlines++;
      p[i] = buf[i];
    }
    orig_text.end[-1] = ')';
  }

  struct Token {
    enum Type {OTHER, ID, AS, TYPE, COMMA, FROM} type;
    string id;
  };
  Token get_token() {
    Token ret {Token::OTHER};
    auto & id = ret.id;
    if (asc_isalpha(*p) || *p == '*') {
      get_id(id);
      if (eq_icase(id, "as")) {
	if (!asc_isalpha(*p)) return ret;
	get_id(id);
	ret.type = Token::AS;
      } else if (eq_icase(id, "from")) {
	ret.type = Token::FROM;
      } else {
	// skip over table names
	while (p != NULL && *p == '.') {
	  adv(); skipspace();
	  if (!(asc_isalpha(*p) || *p == '*')) return ret;
	  get_id(id);
	}
	ret.type = Token::ID;
      }
    } else if (*p == ',') {
      adv(); skipspace();
      ret.type = Token::COMMA;
    } else if (*p == '`') {
      adv(false); skipspace(false);
      if (!asc_isalpha(*p)) return ret;
      get_id(ret.id, false);
      ret.type = Token::TYPE;
    } else if (proc_special()) {
      /* nothing to do */
    } else {
      adv(); skipspace();
    }
    return ret;
  }

  Column get_column() {
    string id;
    string type;
    while (p != NULL) {
      auto tok = get_token();
      switch (tok.type) {
      case Token::OTHER: 
	id.clear();
	type.clear();
	break;
      case Token::ID:
      case Token::AS:
	id = tok.id;
	break;
      case Token::TYPE:
	type = tok.id;
	break;
      case Token::COMMA:
	return {id, type, false};
      case Token::FROM: 
	return {id, type, true};
      }
    }
    return {id, type, true};
  }

  void proc_select() {
    while (p != NULL) {
      auto res = get_column();
      columns.push_back(res);
      if (res.last) break;
    }
  }

  void proc_rest() {
    while (p != NULL) {
      if (proc_special()) {
	/* nothing to do */
      } else {
	adv();
      }
    }
  }

  bool proc_special() {
    if (*p == '(') proc_group(')');
    else if (*p == '\'') proc_single_quote();
    else if (*p == '$') proc_dollar();
    else return false;
    return true;
  }

  void skipspace(bool output = true) {
  again:
    if (p == NULL) return;
    if (asc_isspace(*p)) {adv(output); goto again;}
    if (p[0] == '-' && p[1] == '-') {adv(output); adv(output); while (p != NULL && *p != '\n') adv(output); goto again;}
    if (p[0] == '/' && p[1] == '*') {adv(output); adv(output); while (p != NULL && !(p[0] == '*' && p[1] == '/')) adv(output); goto again;}
  }

  void proc_group(char close) {
    adv();
    while (p != NULL && *p != close) {
      skipspace();
      bool res = proc_special();
      if (!res) adv();
    }
    skipspace();
  }

  void proc_single_quote() {
    adv();
    while (p != NULL && *p != '\'')
      adv();
    adv();
    skipspace();
  }

  void clear_orig() {
    blank(orig_text.begin, parts[0].begin);
    for (unsigned i = 0; i + 1 < parts.size(); ++i)
      blank(parts[i].end, parts[i+1].begin);
    blank(parts.back().end, orig_text.end);
  }

  void blank(char * b, char * e) {
    assert(b <= e);
    while (b < e) {
      if (!asc_isspace(*b)) *b = ' ';
      ++b;
    }
  }
  
  void try_id(string & res) {
    char * begin = this->p;
    char * p = this->p;
    while (p && (asc_isalpha(*p) || asc_isdigit(*p))) ++p;
    res.assign(begin,p);
  }

  void get_id(string & res, bool output = true) {
    char * begin = p;
    if (*p == '*') {
      ++p;
    } else {
      while (asc_isalpha(*p) || asc_isdigit(*p)) ++p;
    }
    if (output) query.append(begin, p);
    res.assign(begin,p);
    blank(begin, p);
    adv0();
    skipspace();
  }

  void adv0() {
    if (p == itr->end) {
      itr++;
      if (itr != parts.end()) {
	query.append("\\n");
	p = itr->begin;
      } else {
	p = NULL;
      }
    }
  }

  void adv(bool output = true) {
    if (output) query += *p;
    *p = ' ';
    ++p;
    adv0();
  }

  void proc_dollar() {
    query += '?';
    if (splice_count > 0)
      *p = ',';
    else
      *p = ' ';
    splice_count++;
    ++p;
    for (;;) {
      if (asc_isalpha(*p) || asc_isdigit(*p)) ++p;
      else if (*p == '.') ++p;
      else if (p[0] == ':' && p[1] == ':') p += 2;
      else if (p[0] == '-' && p[1] == '>') p += 2;
      else break;
    }
    adv0();
  }

};

void Main::proc_sql(SubStr orig, vector<SubStr>&& p, size_t sz, const char * what) {
  ProcSql proc_sql(orig,std::move(p), sz, what);
  proc_sql.main();
}



// const char * unescape_char(const char * s, const char * end, string & out) {
//   ++s;
//   if (s == end) throw error(si, s, "Unexpected EOS when parsing escape sequence.");
//   switch (*s) {
//   case 'a': out += '\a'; return s + 1;
//   case 'b': out += '\b'; return s + 1;
//   case 'f': out += '\f'; return s + 1;
//   case 'n': out += '\n'; return s + 1;
//   case 'r': out += '\r'; return s + 1;
//   case 't': out += '\t'; return s + 1;
//   case 'v': out += '\v'; return s + 1;
//   case 'x': {
//     // hex 
//     ++s;
//     char * e = (char *)s;
//     unsigned val = strtol(s, &e, 16);
//     if (s == e) throw error(SourceStr(si, s-2, s), "Invalid hex escape sequence.");
//     if (val > 255) throw error(SourceStr(si, s, e), "Value %u is not between 0-255 in hex escape sequence.", val);
//     s = e;
//     out += (char)val;
//     return s;
//   } 
//   case '0': case '1': case '2': case '3': case '4': case '5': case '6': case '7': {
//     // oct
//     const char * b = s;
//     unsigned val = *s - '0'; ++s;
//     if (s != end && '0' <= *s && *s <= '7') {val *= 8; val += *s - '0'; ++s;}
//     if (s != end && '0' <= *s && *s <= '7') {val *= 8; val += *s - '0'; ++s;}
//     if (val > 255) throw error(SourceStr(si, b, s), "Value %u is not between 0-255 in octal escape sequence.", val);
//     out += (char)val;
//     return s;
//   } 
//   default:
//     out += *s;
//     return s + 1;
//   }
// }

int main() {
  Main main_c;
  return main_c.main();
};
