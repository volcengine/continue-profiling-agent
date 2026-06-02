## Build libbpf and bpftool from submodules and expose their outputs
function(cpa_bpf_build_libs)
    set(libbpf_dir "${CPA_BPF_LIBS_DIR}/libbpf")
    set(libbpf_a "${libbpf_dir}/libbpf.a")
    set(CPA_BPF_LIBBPF_A "${libbpf_a}" PARENT_SCOPE)
    cpa_bpf_wrap_quiet_command(
        libbpf_build_cmd
        "libbpf_build"
        "${CMAKE_COMMAND}"
        -E
        env
        "OBJDIR=${libbpf_dir}"
        "CPPFLAGS=-fPIC"
        make
        -C
        "${CMAKE_SOURCE_DIR}/bpf/libbpf/src"
        BUILD_STATIC_ONLY=1
        all
    )
    cpa_bpf_wrap_quiet_command(
        libbpf_headers_cmd
        "libbpf_install_headers"
        "${CMAKE_COMMAND}"
        -E
        env
        "INCLUDEDIR=${libbpf_dir}/include"
        "DESTDIR="
        make
        -C
        "${CMAKE_SOURCE_DIR}/bpf/libbpf/src"
        install_headers
    )

    ## Build libbpf as a static library and install headers into a private directory
    add_custom_command(
        OUTPUT "${libbpf_a}"
        COMMAND "${CMAKE_COMMAND}" -E make_directory "${libbpf_dir}"
        COMMAND ${libbpf_build_cmd}
        COMMAND ${libbpf_headers_cmd}
        BYPRODUCTS "${libbpf_dir}/include"
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
    )
    add_custom_target(cpa_bpf_libbpf DEPENDS "${libbpf_a}")

    ## Copy libbpf.a into bin for distribution convenience
    add_custom_command(
        OUTPUT "${CPA_BPF_BIN_DIR}/libbpf.a"
        COMMAND "${CMAKE_COMMAND}" -E make_directory "${CPA_BPF_BIN_DIR}"
        COMMAND "${CMAKE_COMMAND}" -E copy "${libbpf_a}" "${CPA_BPF_BIN_DIR}/libbpf.a"
        DEPENDS "${libbpf_a}"
    )
    add_custom_target(cpa_bpf_libbpf_bin DEPENDS "${CPA_BPF_BIN_DIR}/libbpf.a")
    add_dependencies(cpa_bpf_libbpf_bin cpa_bpf_libbpf)

    set(bpftool_output "${CPA_BPF_LIBS_DIR}/bpftool")
    set(bpftool_bin "${bpftool_output}/bpftool")
    set(CPA_BPF_BPFTOOL "${bpftool_bin}" PARENT_SCOPE)
    cpa_bpf_wrap_quiet_command(
        bpftool_build_cmd
        "bpftool_build"
        "${CMAKE_COMMAND}"
        -E
        env
        "VMLINUX_BTF_PATHS="
        make
        -C
        "${CMAKE_SOURCE_DIR}/bpf/bpftool/src"
        "OUTPUT=${bpftool_output}/"
        "BPF_DIR=${CMAKE_SOURCE_DIR}/bpf/libbpf/src"
        "LIBBPF_OUTPUT=${libbpf_dir}/"
        "LIBBPF_DESTDIR=${libbpf_dir}/"
    )

    ## Build bpftool using the same libbpf output to avoid duplicate builds
    add_custom_command(
        OUTPUT "${bpftool_bin}"
        COMMAND "${CMAKE_COMMAND}" -E make_directory "${bpftool_output}"
        COMMAND ${bpftool_build_cmd}
        COMMAND /bin/chmod +x "${bpftool_bin}"
        DEPENDS cpa_bpf_libbpf
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
    )
    add_custom_target(cpa_bpf_bpftool DEPENDS "${bpftool_bin}")

    ## Copy bpftool into bin for distribution convenience
    add_custom_command(
        OUTPUT "${CPA_BPF_BIN_DIR}/bpftool"
        COMMAND "${CMAKE_COMMAND}" -E make_directory "${CPA_BPF_BIN_DIR}"
        COMMAND "${CMAKE_COMMAND}" -E copy "${bpftool_bin}" "${CPA_BPF_BIN_DIR}/bpftool"
        DEPENDS "${bpftool_bin}"
    )
    add_custom_target(cpa_bpf_bpftool_bin DEPENDS "${CPA_BPF_BIN_DIR}/bpftool")
    add_dependencies(cpa_bpf_bpftool_bin cpa_bpf_bpftool)
endfunction()

function(cpa_bpf_define_deps)
    cpa_bpf_build_libs()
    set(CPA_BPF_LIBBPF_A "${CPA_BPF_LIBBPF_A}" PARENT_SCOPE)
    set(CPA_BPF_BPFTOOL "${CPA_BPF_BPFTOOL}" PARENT_SCOPE)
endfunction()
