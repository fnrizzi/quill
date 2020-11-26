/**
 * Copyright(c) 2020-present, Odysseas Georgoudis & quill contributors.
 * Distributed under the MIT License (http://opensource.org/licenses/MIT)
 */

#pragma once

#include "quill/detail/misc/TypeTraitsCopyable.h"

namespace quill
{
namespace detail
{
/**
 * Below are type traits to determine whether an object is serializable by our internal serialization.
 */

/**
 * Default is based on std::is_fundamental type as all of them are supported if it is true
 *
 * We serialize pointers as strings, the the pointer is not a string we still serialize and
 * print the pointer value. All this happens in the serialization logic, here we just pass it as true
 *
 * We also serialize enums to their underlyign type
 */
template <typename T>
struct is_serializable_helper
  : public disjunction<std::is_fundamental<T>, std::is_pointer<T>, std::is_enum<T>,
                       std::is_same<std::string, T>, std::is_same<std::wstring, T>>
{
};

template <typename T>
struct is_serializable : public is_serializable_helper<remove_cvref_t<std::decay_t<T>>>
{
};

template <typename... TArgs>
struct is_all_serializable : conjunction<is_serializable<TArgs>...>
{
};

} // namespace detail
} // namespace quill