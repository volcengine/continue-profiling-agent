// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

mod ui;

use crate::profile::UiProfile;

pub fn run(profile: UiProfile, start: usize, span: usize, timing: bool) -> anyhow::Result<()> {
    ui::run(profile, start, span, timing)
}
