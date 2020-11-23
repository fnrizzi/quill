/**
 * Copyright(c) 2020-present, Odysseas Georgoudis & quill contributors.
 * Distributed under the MIT License (http://opensource.org/licenses/MIT)
 */

#pragma once
#include "quill/detail/events/LogRecordMetadata.h"

#include <cstdint> // for size_t
#include <iostream>
#include <memory> // for allocator, unique_ptr
#include <mutex>  // for lock_guard
#include <string> // for string, hash
#include <type_traits>

namespace quill
{
namespace detail
{

/** Type String Info Traits **/

template <typename T>
inline std::string get_type_info()
{
  return {};
}

template <>
inline std::string get_type_info<int8_t>()
{
  return "%I8";
}

template <>
inline std::string get_type_info<int16_t>()
{
  return "%I16";
}

template <>
inline std::string get_type_info<int32_t>()
{
  return "%I32";
}

template <>
inline std::string get_type_info<int64_t>()
{
  return "%I64";
}

template <>
inline std::string get_type_info<uint8_t>()
{
  return "%U8";
}

template <>
inline std::string get_type_info<uint16_t>()
{
  return "%U16";
}

template <>
inline std::string get_type_info<uint32_t>()
{
  return "%U32";
}

template <>
inline std::string get_type_info<uint64_t>()
{
  return "%U64";
}

template <>
inline std::string get_type_info<double>()
{
  return "%D";
}

template <>
inline std::string get_type_info<long double>()
{
  return "%LD";
}

template <>
inline std::string get_type_info<float>()
{
  return "%F";
}

template <>
inline std::string get_type_info<std::string>()
{
  return "%S";
}

template <>
inline std::string get_type_info<char*>()
{
  return "%S";
}

template <>
inline std::string get_type_info<const char*>()
{
  return "%S";
}

template <>
inline std::string get_type_info<char>()
{
  return "%C";
}

template <typename T, size_t N>
inline std::string get_type_info()
{
  return "%S";
}
/** Type String Info Traits End **/

/** Get size **/

template <typename T>
inline size_t get_size(T const&)
{
  return sizeof(T);
}

inline size_t get_size(char* s) { return strlen(s) + 1; }

inline size_t get_size(const char* s) { return strlen(s) + 1; }

inline size_t get_size(std::string&& s) { return s.length() + 1; }

inline size_t get_size(std::string const& s) { return s.length() + 1; }

template <typename T, size_t N>
inline size_t get_size(char*)
{
  return N + 1;
}

template <typename Arg>
inline void get_size_of(size_t& total_size, Arg&& arg)
{
  total_size += get_size(std::forward<Arg>(arg));
}

template <typename Arg, typename... Args>
inline void get_size_of(size_t& total_size, Arg&& arg, Args&&... args)
{
  total_size += get_size(std::forward<Arg>(arg));
  get_size_of(total_size, std::forward<Args>(args)...);
}

/** Get size end **/

/** Store arguments **/

template <typename T>
inline void store_argument(unsigned char*& buffer, T const& arg)
{
  memcpy(buffer, &arg, sizeof(T));
  buffer += sizeof(T);
}

inline void store_argument(unsigned char*& buffer, char* s)
{
  size_t const len = strlen(s);
  memcpy(buffer, s, len);
  buffer += len;
  *buffer = '\0';
  buffer += 1;
}

inline void store_argument(unsigned char*& buffer, const char* s)
{
  size_t const len = strlen(s);
  memcpy(buffer, s, len);
  buffer += len;
  *buffer = '\0';
  buffer += 1;
}

inline void store_argument(unsigned char*& buffer, std::string&& s)
{
  memcpy(buffer, s.data(), s.length());
  buffer += s.length();
  *buffer = '\0';
  buffer += 1;
}

inline void store_argument(unsigned char*& buffer, std::string const& s)
{
  memcpy(buffer, s.data(), s.length());
  buffer += s.length();
  *buffer = '\0';
  buffer += 1;
}

template <typename T, size_t N>
inline size_t store_argument(unsigned char*& buffer, char* s)
{
  memcpy(buffer, s, N);
  buffer += N;
  *buffer = '\0';
  buffer += 1;
}

template <typename Arg>
inline void store_arguments(unsigned char*& buffer, Arg&& arg)
{
  store_argument(buffer, std::forward<Arg>(arg));
}

template <typename Arg, typename... Args>
inline void store_arguments(unsigned char*& buffer, Arg&& arg, Args&&... args)
{
  store_argument(buffer, std::forward<Arg>(arg));
  store_arguments(buffer, std::forward<Args>(args)...);
}

/** Store arguments end **/

template <typename... Args>
inline typename std::enable_if<sizeof...(Args) == 0>::type append_type_info(std::string&)
{
}

template <typename Arg, typename... Args>
inline void append_type_info(std::string& s)
{
  s += get_type_info<Arg>();
  append_type_info<Args...>(s);
}

template <typename... Args>
inline std::string get_type_info_string()
{
  std::string s;
  s.reserve(8);
  append_type_info<Args...>(s);
  return s;
}

struct LogDataNode
{
  LogDataNode(std::string in_type_info_data, LogRecordMetadata const& in_metadata)
    : type_info_data(std::move(in_type_info_data)), metadata(in_metadata)
  {
  }

  std::string type_info_data;
  LogRecordMetadata metadata;
};

/**
 * Creates a static LogDataNode pointer during program init
 * @return
 */
template <typename F, typename... Args>
inline LogDataNode const* get_log_data_node_ptr()
{
  static auto log_data_node = LogDataNode{get_type_info_string<std::decay_t<Args>...>(), F{}()};
  return &log_data_node;
}

/**
 * A wrapper around LogDataNode.
 */
struct LogDataNodeWrapper
{
  explicit LogDataNodeWrapper(LogDataNode const* in_log_data_node) : log_data_node(in_log_data_node)
  {
  }
  LogDataNode const* log_data_node{nullptr};
};

/**
 * A variable template that will call get_log_data_node_ptr during the program initialisation time
 */
template <typename F, typename... Args>
LogDataNodeWrapper log_data_node_wrapper{get_log_data_node_ptr<F, Args...>()};

} // namespace detail
} // namespace quill