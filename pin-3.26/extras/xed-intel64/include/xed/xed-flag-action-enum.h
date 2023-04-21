/* BEGIN_LEGAL 

Copyright (c) 2022 Intel Corporation

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
  
END_LEGAL */
/// @file xed-flag-action-enum.h

// This file was automatically generated.
// Do not edit this file.

#if !defined(XED_FLAG_ACTION_ENUM_H)
# define XED_FLAG_ACTION_ENUM_H
#include "xed-common-hdrs.h"
#define XED_FLAG_ACTION_INVALID_DEFINED 1
#define XED_FLAG_ACTION_u_DEFINED 1
#define XED_FLAG_ACTION_tst_DEFINED 1
#define XED_FLAG_ACTION_mod_DEFINED 1
#define XED_FLAG_ACTION_0_DEFINED 1
#define XED_FLAG_ACTION_pop_DEFINED 1
#define XED_FLAG_ACTION_ah_DEFINED 1
#define XED_FLAG_ACTION_1_DEFINED 1
#define XED_FLAG_ACTION_LAST_DEFINED 1
typedef enum {
  XED_FLAG_ACTION_INVALID,
  XED_FLAG_ACTION_u, ///< undefined (treated as a write)
  XED_FLAG_ACTION_tst, ///< test (read)
  XED_FLAG_ACTION_mod, ///< modification (write)
  XED_FLAG_ACTION_0, ///< value will be zero (write)
  XED_FLAG_ACTION_pop, ///< value comes from the stack (write)
  XED_FLAG_ACTION_ah, ///< value comes from AH (write)
  XED_FLAG_ACTION_1, ///< value will be 1 (write)
  XED_FLAG_ACTION_LAST
} xed_flag_action_enum_t;

/// This converts strings to #xed_flag_action_enum_t types.
/// @param s A C-string.
/// @return #xed_flag_action_enum_t
/// @ingroup ENUM
XED_DLL_EXPORT xed_flag_action_enum_t str2xed_flag_action_enum_t(const char* s);
/// This converts strings to #xed_flag_action_enum_t types.
/// @param p An enumeration element of type xed_flag_action_enum_t.
/// @return string
/// @ingroup ENUM
XED_DLL_EXPORT const char* xed_flag_action_enum_t2str(const xed_flag_action_enum_t p);

/// Returns the last element of the enumeration
/// @return xed_flag_action_enum_t The last element of the enumeration.
/// @ingroup ENUM
XED_DLL_EXPORT xed_flag_action_enum_t xed_flag_action_enum_t_last(void);
#endif
