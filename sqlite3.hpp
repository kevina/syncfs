#include <vector>
#include <string>
#include <algorithm>

#include <sqlite3.h>

extern bool db_locked;
extern sqlite3 *db;
extern std::vector<class SqlStmtBase *> sql_stmts;

struct Path {
  const char * str;
  Path(const char * str) : str(str) {}
};

struct CharBuf {
  char * str;
  size_t sz;
};

struct SqlError {
  int retcode;
  int code;
  std::string msg;
  SqlError(int retcode, sqlite3 * db) : retcode(retcode) 
  {
    code = sqlite3_errcode(db);
    msg = sqlite3_errmsg(db);
  }
  SqlError(const char * msg) : retcode(), code(), msg(msg) {}
  SqlError(std::string && msg) : retcode(), code(), msg(std::move(msg)) {}
  SqlError & w_query(std::string && q) {msg = '"' + q + "\": " + msg; return *this;}
};

class SqlStmtBase {
public:
  SqlStmtBase(const char * sql) : sql(sql), stmt(NULL) {
    sql_stmts.push_back(this);
  }
  SqlStmtBase(const SqlStmtBase &) = delete;
  void operator=(const SqlStmtBase &) = delete;
  ~SqlStmtBase() {
    auto pos = std::find(sql_stmts.begin(), sql_stmts.end(), this);
    sql_stmts.erase(pos);
  }
  void prepare() {
    assert(db_locked);
    if (stmt == NULL) {
      int res = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
      if (res != 0) throw SqlError(res, db).w_query(sql);
    }
  }
  const char * const sql;
protected:
  sqlite3_stmt * stmt;
  int bind(int & idx, int val) {return sqlite3_bind_int(stmt, idx++, val);}
  int bind(int & idx, long int val) {return sqlite3_bind_int64(stmt, idx++, val);}
  int bind(int & idx, long long int val) {return sqlite3_bind_int64(stmt, idx++, val);}
  int bind(int & idx, const char * val) {return sqlite3_bind_text(stmt, idx++, val, -1, SQLITE_STATIC);};
  int bind(int & idx, Path val) {
    const char * pos = strrchr(val.str, '/');
    assert(pos);
    pos++;
    int res = sqlite3_bind_text(stmt, idx++, val.str, pos - val.str, SQLITE_STATIC);
    if (res != 0) return res;
    return sqlite3_bind_text(stmt, idx++, pos, -1,  SQLITE_STATIC);
  }
};

class SqlStmt : public SqlStmtBase {
public:
  SqlStmt(const char * sql) : SqlStmtBase(sql) {}
  void exec0(int idx) {
    assert(db_locked);
    if (idx - 1 != sqlite3_bind_parameter_count(stmt))
      throw SqlError(std::string("Wrong number of binding parameters for query: ") + sql);
    int res = sqlite3_step(stmt);
    if (res != SQLITE_DONE) throw SqlError(res, db);
    sqlite3_reset(stmt);
    sqlite3_clear_bindings(stmt);
  }
  template<typename T, typename... Ts> void exec0(int idx, T arg, Ts... args) {
    int res = bind(idx, arg);
    if (res != 0) throw SqlError(res, db);
    exec0(idx, args...);
  }
  // execute statement
  template<typename... Ts> void exec_nocheck(Ts... args) {
    prepare(); 
    exec0(1, args...);
  }  
  // execute statement, and check that it did something
  template<typename... Ts> void exec(Ts... args) {
    exec_nocheck(args...);
    if (sqlite3_changes(db) <= 0) 
      throw SqlError(std::string("No rows modifed while executing: ") + sql);
  }

  // execite statement, and check that exactly one row was changed
  template<typename... Ts> void exec1(Ts... args) {
    exec(args...);
    if (sqlite3_changes(db) > 1)
      throw SqlError(std::string("More than one row modifed while executing: ") + sql);
  }
};

class SqlResult {
public:
  SqlResult() : db(), stmt() {}
  SqlResult(sqlite3 * db, sqlite3_stmt * stmt) : db(db), stmt(stmt) {}
  SqlResult(SqlResult && other) 
    : db(other.db), stmt(other.stmt) {other.stmt = NULL;}
  SqlResult & operator=(SqlResult && other) {
    reset();
    db = other.db;
    stmt = other.stmt;
    other.stmt = NULL;
    return *this;
  }
  bool step() {
    assert(db_locked);
    int res = sqlite3_step(stmt);
    if (res == SQLITE_DONE) return false;
    if (res == SQLITE_ROW) return true;
    else throw SqlError(res, db);
  }
  void get0(int idx) {}
  template<typename T, typename... Ts> void get0(int idx, T & arg, Ts & ... args) {
    get_column(idx, arg);
    get0(idx + 1, args...);
  }
  template<typename... Ts> void get(Ts & ... args) {get0(0, args...);}
  void reset() {
    if (stmt) {
      assert(db_locked);
      sqlite3_reset(stmt);
      sqlite3_clear_bindings(stmt);
      stmt = NULL;
    }
  }
  ~SqlResult() {
    reset();
  }
protected:
  sqlite3 * db;
  sqlite3_stmt * stmt;
  void get_column(int idx, const char * & val) {val = (const char *)sqlite3_column_text(stmt, idx);};
  void get_column(int idx, std::string & val) {
    auto val0 = (const char *)sqlite3_column_text(stmt, idx);
    if (val0 == 0) val.clear();
    else val = val0;
  }
  void get_column(int idx, bool & val) {val = (bool)sqlite3_column_int(stmt, idx);};
  void get_column(int idx, int & val) {val = sqlite3_column_int(stmt, idx);};
  void get_column(int idx, unsigned int & val) {val = sqlite3_column_int(stmt, idx);};
  void get_column(int idx, long int & val) {val = (long int)sqlite3_column_int64(stmt, idx);};
  void get_column(int idx, long long int & val) {val = (long int)sqlite3_column_int64(stmt, idx);};
};

class SqlSelect : public SqlStmtBase {
public:
  SqlSelect(const char * sql) : SqlStmtBase(sql) {}
  SqlResult exec0(int) {
    return SqlResult(db, stmt);
  }
  template<typename T, typename... Ts> SqlResult exec0(int idx, T arg, Ts... args) {
    int res = bind(idx, arg);
    if (res != 0) throw SqlError(res, db);
    return exec0(idx, args...);
  }
  template<typename... Ts> SqlResult operator() (Ts... args) {prepare(); return exec0(1, args...);}
};

class SqlSingle : public SqlStmtBase {
public:
  SqlSingle(const char * sql) : SqlStmtBase(sql) {}
  void exec0(int) {}
  template<typename T, typename... Ts> void exec0(int idx, T arg, Ts... args) {
    int res = bind(idx, arg);
    if (res != 0) throw SqlError(res, db);
    exec0(idx, args...);
  }
  template<typename... Ts> SqlSingle & operator() (Ts... args) {prepare(); exec0(1, args...); return *this;}
  template<typename... Ts> void get(Ts & ... args) {
    auto res = SqlResult(db, stmt);
    if (!res.step()) throw SqlError(std::string("Query did not return any result: ") + sql);
    res.get(args...);
  }
};

void sql_exec(const char * sql) {
  assert(db_locked);
  auto ret = sqlite3_exec(db, sql, NULL, NULL, NULL);
  if (ret != 0) throw SqlError(ret, db).w_query(sql);
}

class SqlTrans {
public:
  bool trans_open;
  SqlTrans() {
    assert(db_locked);
    auto res = sqlite3_exec(db, "BEGIN", 0, 0, 0);
    if (res != 0) throw SqlError(res, db);
    trans_open = true;
  }
  void commit() {
    assert(db_locked);
    auto res = sqlite3_exec(db, "COMMIT", 0, 0, 0);
    if (res != 0) throw SqlError(res, db);
    trans_open = false;
  }
  void rollback() {
    assert(db_locked);
    auto res = sqlite3_exec(db, "ROLLBACK", 0, 0, 0);
    if (res != 0) throw SqlError(res, db);
    trans_open = false;
  }
  ~SqlTrans() {
    assert(db_locked);
    if (trans_open)
      sqlite3_exec(db, "ROLLBACK", 0, 0, 0);
  }
};

