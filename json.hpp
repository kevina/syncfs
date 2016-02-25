#include <stdexcept>               // std::runtime_error
#define RAPIDJSON_PARSE_ERROR_NORETURN(parseErrorCode,offset) \
  throw ParseException(parseErrorCode, #parseErrorCode, offset)
#define RAPIDJSON_GET_VALUE_FAILURE(name) \
  throw JsonValueNotFound(name)
#define RAPIDJSON_TEST_TYPE(test, expected, val) \
  do {if (!(test)) throw JsonWrongType("JSON ERROR: Expected " expected "."); } while (false)
#define RAPIDJSON_HAS_CXX11_RVALUE_REFS 1
#define RAPIDJSON_HAS_STDSTRING 1

#include "rapidjson/error/error.h" // rapidjson::ParseResult

struct JsonException : std::runtime_error {
  JsonException(const char * str) : runtime_error(str) {}
  JsonException(const std::string & str) : runtime_error(str) {}
};

struct ParseException : JsonException, rapidjson::ParseResult {
  ParseException(rapidjson::ParseErrorCode code, const char* msg, size_t offset)
    : JsonException(msg), ParseResult(code, offset) {}
};
struct JsonValueNotFound : JsonException {
  template <typename T>
  JsonValueNotFound(const T & val) 
    : JsonException(val.IsString() 
		    ? std::string("JSON ERROR: No value fond for key: ") + val.GetString() 
		    : std::string("JSON ERROR: No value found for non-string key.")) {}
};
struct JsonWrongType : JsonException {
  JsonWrongType(const char * msg) 
    : JsonException(msg) {}
};

#include "rapidjson/document.h"
#include "rapidjson/filereadstream.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"

namespace json = rapidjson;

struct RootObjectBase {
  json::Document doc;
  RootObjectBase(json::Document && doc) : doc(std::move(doc)) {}
  RootObjectBase() {doc.SetObject();}
};

struct RootObject : RootObjectBase, json::Value::Object {
  RootObject(json::Document && d) : RootObjectBase(std::move(d)), Object(doc.GetObject()) {}
  RootObject() : RootObjectBase(), Object(doc.GetObject()) {}
  RootObject(RootObject && other) : RootObjectBase(std::move(other)), Object(doc.GetObject()) {}
  RootObject & operator=(RootObject && other) {
    this->~RootObject();
    new (this) RootObject(std::move(other));
    return *this;
  }
  explicit operator bool() const {return !ObjectEmpty();}
  template <typename Key, typename Val>
  RootObject & AddMember(Key && key, Val && val) {
    Object::AddMember(std::forward<Key>(key), std::forward<Val>(val), doc.GetAllocator());
    return *this;
  }
};

struct RootArrayBase {
  json::Document doc;
  RootArrayBase(json::Document && doc) : doc(std::move(doc)) {}
  RootArrayBase() {doc.SetArray();}
};

struct RootArray : RootArrayBase, json::Value::Array {
  RootArray(json::Document && d) : RootArrayBase(std::move(d)), Array(doc.GetArray()) {}
  RootArray() : RootArrayBase(), Array(doc.GetArray()) {}
  RootArray(RootArray && other) : RootArrayBase(std::move(other)), Array(doc.GetArray()) {}
  RootArray & operator=(RootArray && other) {
    this->~RootArray();
    new (this) RootArray(std::move(other));
    return *this;
  }
  explicit operator bool() const {return !Empty();}
  template <typename Val>
  RootArray & PushBack(Val && val) {
    Array::PushBack(std::forward<Val>(val), doc.GetAllocator());
    return *this;
  }
};

extern json::Value::ConstObject EmptyObject; // defined in zbfs.cpp 

template <typename V, typename T>
static inline V GetMember(const char * key, V def_value, const T & obj) {
  auto i = obj.FindMember(key);
  if (i == obj.MemberEnd()) return def_value;
  else return i->value.template Get<V>();
}
