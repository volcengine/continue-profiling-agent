## Build min_core_btf_tar.o using existing Makefile.btfgen rules
function(generate_btf)
    set(btf_obj "${CPA_BPF_GEN_DIR}/min_core_btf_tar.o")

    file(GLOB_RECURSE btf_tarballs "${CPA_BPF_BTFHUB_ARCHIVE}/*.btf.tar.xz")
    list(REMOVE_DUPLICATES btf_tarballs)

    get_property(bpf_objs GLOBAL PROPERTY CPA_BPF_OBJECTS)

    set(min_core_btfs_dir "${CPA_BPF_GEN_DIR}/min_core_btfs")
    set(min_core_btfs "")
    foreach(tarball IN LISTS btf_tarballs)
        file(RELATIVE_PATH rel_tarball "${CPA_BPF_BTFHUB_ARCHIVE}" "${tarball}")
        string(REGEX REPLACE "\\.tar\\.xz$" "" rel_btf "${rel_tarball}")
        string(REGEX REPLACE "\\.tar\\.xz$" "" src_btf "${tarball}")

        set(dst_btf "${min_core_btfs_dir}/${rel_btf}")
        get_filename_component(dst_dir "${dst_btf}" DIRECTORY)
        get_filename_component(src_dir "${src_btf}" DIRECTORY)

        add_custom_command(
            OUTPUT "${src_btf}"
            COMMAND "${CMAKE_COMMAND}" -E make_directory "${src_dir}"
            COMMAND "${CPA_BPF_TAR}" -xJf "${tarball}" -C "${src_dir}"
            COMMAND "${CMAKE_COMMAND}" -E touch "${src_btf}"
            DEPENDS "${tarball}"
            WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
        )

        add_custom_command(
            OUTPUT "${dst_btf}"
            COMMAND "${CMAKE_COMMAND}" -E make_directory "${dst_dir}"
            COMMAND "${CPA_BPF_BPFTOOL}" gen min_core_btf "${src_btf}" "${dst_btf}" ${bpf_objs}
            DEPENDS "${src_btf}" cpa_bpf_bpftool cpa_bpf_objects
            WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
        )
        list(APPEND min_core_btfs "${dst_btf}")
    endforeach()
    list(REMOVE_DUPLICATES min_core_btfs)

    set(min_core_tar_gz "${CPA_BPF_GEN_DIR}/min_core_btfs.tar.gz")
    add_custom_command(
        OUTPUT "${min_core_tar_gz}"
        COMMAND "${CMAKE_COMMAND}" -E make_directory "${min_core_btfs_dir}"
        COMMAND "${CMAKE_COMMAND}" -E rm -f "${min_core_tar_gz}"
        COMMAND "${CPA_BPF_TAR}" --warning=no-file-changed -czf "${min_core_tar_gz}" -C "${min_core_btfs_dir}" .
        DEPENDS ${min_core_btfs}
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
    )

    add_custom_command(
        OUTPUT "${btf_obj}"
        COMMAND "${CMAKE_COMMAND}" -E make_directory "${CPA_BPF_GEN_DIR}"
        COMMAND "${CPA_BPF_LD_BFD}" -r -b binary "min_core_btfs.tar.gz" -o "${btf_obj}"
        DEPENDS "${min_core_tar_gz}"
        WORKING_DIRECTORY "${CPA_BPF_GEN_DIR}"
    )
    add_custom_target(cpa_bpf_btfgen DEPENDS "${btf_obj}")
    target_sources(${CPA_BPF_CORE_TARGET} PRIVATE "${btf_obj}")
endfunction()

function(cpa_bpf_define_btfgen)
    generate_btf()
endfunction()
