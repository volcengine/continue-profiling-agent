# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 ByteDance

cpa_bpf_add_module(common SOURCES bpf_event_poll.c btf_helpers.c capabilities.c capabilities_libbpf.c core.c trace_helpers.c)
