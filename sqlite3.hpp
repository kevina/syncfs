#include <vector>
#include <string>
#include <algorithm>

#include <sqlite3.h>

#ifdef DEBUG_LOCKS
#include <sys/syscall.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
extern pthread_mutex_t db_mutex;
#define db_locked (db_mutex.__data.__owner == syscall(SYS_gettid))
#else
#define db_locked true
#endif

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

struct SqlStmtInfo {
  const char * const sql;
  sqlite3_stmt * stmt;
  int inline_bound;
};

class SqlStmtBase {
public:
  SqlStmtBase(const char * sql) : inf(new SqlStmtInfo{sql, NULL}) {}
  SqlStmtBase(SqlStmtInfo * i) : inf(i) {}
  void prepare() {
    assert(db_locked);
    if (inf->stmt == NULL) {
      int res = sqlite3_prepare_v2(db, inf->sql, -1, &inf->stmt, NULL);
      if (res != 0) throw SqlError(res, db).w_query(inf->sql);
    }
  }
  SqlStmtInfo * const inf;
protected:
  int bind(int & idx, int val) {return sqlite3_bind_int(inf->stmt, idx++, val);}
  int bind(int & idx, long int val) {return sqlite3_bind_int64(inf->stmt, idx++, val);}
  int bind(int & idx, long long int val) {return sqlite3_bind_int64(inf->stmt, idx++, val);}
  int bind(int & idx, const char * val) {return sqlite3_bind_text(inf->stmt, idx++, val, -1, SQLITE_STATIC);};
  int bind(int & idx, Path val) {
    const char * pos = strrchr(val.str, '/');
    assert(pos);
    pos++;
    int res = sqlite3_bind_text(inf->stmt, idx++, val.str, pos - val.str, SQLITE_STATIC);
    if (res != 0) return res;
    return sqlite3_bind_text(inf->stmt, idx++, pos, -1,  SQLITE_STATIC);
  }
};

class SqlStmt : public SqlStmtBase {
public:
  SqlStmt(const char * sql) : SqlStmtBase(sql) {}
  SqlStmt(SqlStmtInfo * i) : SqlStmtBase(i) {}
  void exec0(int idx) {
    assert(db_locked);
    if (idx - 1 != sqlite3_bind_parameter_count(inf->stmt) - inf->inline_bound)
      throw SqlError(std::string("Wrong number of binding parameters for query: ") + inf->sql);
    int res = sqlite3_step(inf->stmt);
    if (res != SQLITE_DONE) throw SqlError(res, db);
    sqlite3_reset(inf->stmt);
    sqlite3_clear_bindings(inf->stmt);
  }
  template<typename T, typename... Ts> void exec0(int idx, T arg, Ts... args) {
    int res = bind(idx, arg);
    if (res != 0) throw SqlError(res, db);
    exec0(idx, args...);
  }
};

class SqlInsert : public SqlStmt {
public:
  SqlInsert(const char * sql) : SqlStmt(sql) {}
  SqlInsert(SqlStmtInfo * i) : SqlStmt(i) {}
  // execute statement
  template<typename... Ts> int64_t exec(Ts... args) {
    prepare(); 
    exec0(1, args...);
    return sqlite3_last_insert_rowid(db);
  }

  // execite statement, and check that exactly one row was changed
  template<typename... Ts> int64_t exec1(Ts... args) {
    exec(args...);
    if (sqlite3_changes(db) > 1)
      throw SqlError(std::string("More than one row modifed while executing: ") + inf->sql);
    return sqlite3_last_insert_rowid(db);
  }
};

class SqlOther : public SqlStmt {
public:
  SqlOther(const char * sql) : SqlStmt(sql) {}
  SqlOther(SqlStmtInfo * i) : SqlStmt(i) {}
  // execute statement
  template<typename... Ts> void exec_nocheck(Ts... args) {
    prepare(); 
    exec0(1, args...);
  }  
  // execute statement, and check that it did something
  template<typename... Ts> void exec(Ts... args) {
    exec_nocheck(args...);
    if (sqlite3_changes(db) <= 0) 
      throw SqlError(std::string("No rows modifed while executing: ") + inf->sql);
  }

  // execite statement, and check that exactly one row was changed
  template<typename... Ts> void exec1(Ts... args) {
    exec(args...);
    if (sqlite3_changes(db) > 1)
      throw SqlError(std::string("More than one row modifed while executing: ") + inf->sql);
  }
};

class SqlResult {
public:
  SqlResult() : db(), stmt(), step_called(false) {}
  SqlResult(sqlite3 * db, sqlite3_stmt * stmt) : db(db), stmt(stmt), step_called(false) {}
  SqlResult(SqlResult && other) 
    : db(other.db), stmt(other.stmt), step_called(other.step_called) {other.stmt = NULL;}
  SqlResult & operator=(SqlResult && other) {
    reset();
    db = other.db;
    stmt = other.stmt;
    step_called = other.step_called;
    other.stmt = NULL;
    return *this;
  }
  bool step() {
    assert(db_locked);
    int res = sqlite3_step(stmt);
    step_called = 2;
    if (res == SQLITE_DONE) return false;
    if (res == SQLITE_ROW) return true;
    else throw SqlError(res, db);
  }
  void get0(int idx) {}
  template<typename T, typename... Ts> void get0(int idx, T & arg, Ts & ... args) {
    get_column(idx, arg);
    get0(idx + 1, args...);
  }
  template<typename... Ts> void get(Ts & ... args) {
    if (!step_called)
      if (!step()) throw SqlError("Query did not return any result.");
    get0(0, args...);
  }
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
  int8_t step_called; // 0 = step never called, 1 = step called and we got the data, 2 = step called and we didn't get the data
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

template <typename Res = SqlResult>
class SqlSelect : public SqlStmtBase {
public:
  SqlSelect(const char * sql) : SqlStmtBase(sql) {}
  SqlSelect(SqlStmtInfo * i) : SqlStmtBase(i) {}
  Res exec0(int) {
    return Res(db, inf->stmt);
  }
  template<typename T, typename... Ts> Res exec0(int idx, T arg, Ts... args) {
    int res = bind(idx, arg);
    if (res != 0) throw SqlError(res, db);
    return exec0(idx, args...);
  }
  template<typename... Ts> Res operator() (Ts... args) {prepare(); return exec0(1, args...);}

  template<typename... Ts> void get(Ts & ... args) {
    operator()();
    auto res = Res(db, inf->stmt);
    if (!res.step()) throw SqlError(std::string("Query did not return any result: ") + inf->sql);
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

