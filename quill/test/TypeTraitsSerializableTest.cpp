#include "doctest/doctest.h"

#include "quill/detail/misc/TypeTraitsSerializable.h"
#include <array>
#include <chrono>
#include <cstdint>
#include <ctime>
#include <functional>
#include <map>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

TEST_SUITE_BEGIN("TypeTraitsSerializable");

using namespace quill::detail;

struct Trivial
{
  int a;
};

struct NonTrivial
{
public:
  explicit NonTrivial(std::string x) : x(std::move(x)){};

private:
  std::string x;
};

enum Enum
{
  One,
  Two
};

enum class EnumClass
{
  Three,
  Four
};

TEST_CASE("is_serializable")
{
  static_assert(is_serializable<std::string>::value, "_");
  static_assert(is_serializable<std::wstring>::value, "_");
  static_assert(is_serializable<uint32_t>::value, "_");
  static_assert(is_serializable<float>::value, "_");
  static_assert(is_serializable<char>::value, "_");
  static_assert(is_serializable<wchar_t>::value, "_");
  static_assert(is_serializable<bool>::value, "_");

  char const* s1 = "test";
  static_assert(is_serializable<decltype(s1)>::value, "_");
  char const s2[] = "test";
  static_assert(is_serializable<decltype(s2)>::value, "_");

  wchar_t const* ws1 = L"test";
  static_assert(is_serializable<decltype(ws1)>::value, "_");
  wchar_t const ws2[] = L"test";
  static_assert(is_serializable<decltype(ws2)>::value, "_");

  static_assert(is_serializable<EnumClass>::value, "_");
  static_assert(is_serializable<Enum>::value, "_");

  static_assert(!is_serializable<NonTrivial>::value, "_");
  static_assert(!is_serializable<Trivial>::value, "_");
  static_assert(!is_serializable<std::vector<int>>::value, "_");
  static_assert(!is_serializable<std::pair<int, int>>::value, "_");
  static_assert(!is_serializable<std::array<int, 10>>::value, "_");
}

TEST_CASE("is_all_serializable")
{
  static_assert(is_all_serializable<uint32_t, uint64_t, std::wstring>::value, "_");
  static_assert(!is_all_serializable<uint32_t, NonTrivial>::value, "_");
}

TEST_SUITE_END();