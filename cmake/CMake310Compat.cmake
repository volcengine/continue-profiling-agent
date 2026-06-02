# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 ByteDance Inc.

if(NOT COMMAND cpa_find_required_program)
    function(cpa_find_required_program out_var)
        find_program(${out_var} ${ARGN})
        if(NOT ${out_var})
            string(REPLACE ";" " " _cpa_find_args "${ARGN}")
            message(
                FATAL_ERROR
                "required program not found for ${out_var}: ${_cpa_find_args}. "
                "Set -D${out_var}=/path/to/program or update PATH."
            )
        endif()
        set(${out_var} "${${out_var}}" PARENT_SCOPE)
    endfunction()
endif()
