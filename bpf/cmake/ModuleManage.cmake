## Central target name for all host objects
set(CPA_BPF_CORE_TARGET cpa_bpf_core)

set_property(GLOBAL PROPERTY CPA_BPF_OBJECTS "")
set_property(GLOBAL PROPERTY CPA_BPF_APPS "")
set_property(GLOBAL PROPERTY CPA_BPF_SKELS "")

if(NOT TARGET cpa_bpf_objects)
    add_custom_target(cpa_bpf_objects)
endif()

if(NOT TARGET cpa_bpf_skeletons)
    add_custom_target(cpa_bpf_skeletons)
endif()

## Compile .bpf.c into .bpf.o and generate .skel.h with bpftool
function(add_bpf_skeleton out_skel out_obj bpf_name bpf_source bpf_include_dir)
    set(obj_path "${CPA_BPF_GEN_DIR}/${bpf_name}.bpf.o")
    set(skel_path "${CPA_BPF_GEN_DIR}/${bpf_name}.skel.h")

    set(bpf_include_flags "")
    foreach(dir IN LISTS CPA_BPF_INCLUDE_DIRS)
        list(APPEND bpf_include_flags "-I${dir}")
    endforeach()
    list(APPEND bpf_include_flags "-I${bpf_include_dir}")

    ## BPF object compilation
    add_custom_command(
        OUTPUT "${obj_path}"
        COMMAND "${CMAKE_COMMAND}" -E make_directory "${CPA_BPF_GEN_DIR}"
        COMMAND "${CPA_BPF_CLANG}"
            -g -O2 -Wall -target bpf
            "-D__TARGET_ARCH_${CPA_BPF_ARCH}"
            "-D__CPA_BPF_ARCH_${CPA_BPF_ARCH}"
            ${bpf_include_flags}
            -c "${bpf_source}"
            -o "${obj_path}"
        COMMAND "${CPA_BPF_LLVM_STRIP}" -g "${obj_path}"
        DEPENDS "${bpf_source}" cpa_bpf_libbpf
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
    )

    ## Skeleton generation
    add_custom_command(
        OUTPUT "${skel_path}"
        COMMAND "${CMAKE_COMMAND}" -E make_directory "${CPA_BPF_GEN_DIR}"
        COMMAND "${CPA_BPF_BPFTOOL}" gen skeleton "${obj_path}" > "${skel_path}"
        DEPENDS "${obj_path}" cpa_bpf_bpftool
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
    )

    set(${out_skel} "${skel_path}" PARENT_SCOPE)
    set(${out_obj} "${obj_path}" PARENT_SCOPE)
endfunction()

## Register a module: add host C sources and optionally generate BPF skeletons
function(add_module name)
    cmake_parse_arguments(ARG "" "" "SOURCES;BPF_SOURCES" ${ARGN})
    set(module_dir "${CMAKE_CURRENT_LIST_DIR}")
    set(host_sources "")

    ## Collect host-side C sources
    if(ARG_SOURCES)
        foreach(src IN LISTS ARG_SOURCES)
            list(APPEND host_sources "${module_dir}/${src}")
        endforeach()
    else()
        if(EXISTS "${module_dir}/${name}.c")
            list(APPEND host_sources "${module_dir}/${name}.c")
        endif()
    endif()

    ## Add host sources to core library and include module directory
    if(host_sources)
        target_sources(${CPA_BPF_CORE_TARGET} PRIVATE ${host_sources})
        target_include_directories(${CPA_BPF_CORE_TARGET} PRIVATE "${module_dir}")
    endif()

    set(bpf_source "")
    ## Detect BPF source file
    if(ARG_BPF_SOURCES)
        set(bpf_source "${module_dir}/${ARG_BPF_SOURCES}")
    else()
        if(EXISTS "${module_dir}/${name}.bpf.c")
            set(bpf_source "${module_dir}/${name}.bpf.c")
        endif()
    endif()

    ## Generate skeleton and wire host sources to depend on it
    if(bpf_source)
        add_bpf_skeleton(skel_header bpf_obj "${name}" "${bpf_source}" "${module_dir}")
        set_source_files_properties(${host_sources} PROPERTIES OBJECT_DEPENDS "${skel_header}")
        set_property(GLOBAL APPEND PROPERTY CPA_BPF_OBJECTS "${bpf_obj}")
        set_property(GLOBAL APPEND PROPERTY CPA_BPF_APPS "${name}")
        set_property(GLOBAL APPEND PROPERTY CPA_BPF_SKELS "${skel_header}")
        add_custom_target("cpa_bpf_obj_${name}" DEPENDS "${bpf_obj}")
        add_custom_target("cpa_bpf_skel_${name}" DEPENDS "${skel_header}")
        add_dependencies(cpa_bpf_objects "cpa_bpf_obj_${name}")
        add_dependencies(cpa_bpf_skeletons "cpa_bpf_skel_${name}")
    endif()
endfunction()

function(cpa_bpf_add_bpf_skeleton out_skel out_obj bpf_name bpf_source bpf_include_dir)
    add_bpf_skeleton(${out_skel} ${out_obj} ${bpf_name} ${bpf_source} ${bpf_include_dir})
endfunction()

function(cpa_bpf_add_module name)
    add_module(${name} ${ARGN})
endfunction()
