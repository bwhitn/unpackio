//! Validation and scheduling for hostile-input coder graphs.

use crate::{
    Result,
    model::BindPair,
    parse_util::{ParseControl, format_error, try_reserve, u64_to_usize, usize_to_u64},
    raw::{RawBindPair, RawFolder},
};

pub(crate) struct ValidatedGraph {
    pub(crate) bind_pairs: Box<[BindPair]>,
    pub(crate) packed_input_indices: Box<[u64]>,
    pub(crate) root_output_index: u64,
    pub(crate) topological_coder_order: Box<[u64]>,
}

fn false_vector(count: u64, detail: &'static str) -> Result<Vec<bool>> {
    let count = u64_to_usize(count, detail)?;
    let mut values = Vec::new();
    try_reserve(&mut values, count)?;
    #[allow(clippy::same_item_push)]
    for _ in 0..count {
        values.push(false);
    }
    Ok(values)
}

fn owner_for_port(owners: &[usize], index: u64, detail: &'static str) -> Result<usize> {
    let index = u64_to_usize(index, "stream index is not representable on this platform")?;
    owners
        .get(index)
        .copied()
        .ok_or_else(|| format_error(detail))
}

fn validate_bind_pair(
    raw: &RawBindPair,
    input_used: &mut [bool],
    output_used: &mut [bool],
) -> Result<BindPair> {
    let input_index = u64_to_usize(
        raw.input,
        "bind-pair input index is not representable on this platform",
    )?;
    let output_index = u64_to_usize(
        raw.output,
        "bind-pair output index is not representable on this platform",
    )?;
    let input = input_used
        .get_mut(input_index)
        .ok_or_else(|| format_error("bind-pair input index is out of range"))?;
    if *input {
        return Err(format_error("bind-pair input index is duplicated"));
    }
    *input = true;
    let output = output_used
        .get_mut(output_index)
        .ok_or_else(|| format_error("bind-pair output index is out of range"))?;
    if *output {
        return Err(format_error("bind-pair output index is duplicated"));
    }
    *output = true;
    Ok(BindPair::new(raw.input, raw.output))
}

fn topological_order(
    coder_count: usize,
    input_owners: &[usize],
    output_owners: &[usize],
    bind_pairs: &[RawBindPair],
    control: &mut ParseControl<'_>,
) -> Result<Box<[u64]>> {
    let mut indegree = Vec::new();
    try_reserve(&mut indegree, coder_count)?;
    indegree.resize(coder_count, 0_u64);
    let mut edges = Vec::new();
    try_reserve(&mut edges, bind_pairs.len())?;
    for pair in bind_pairs {
        let source = owner_for_port(
            output_owners,
            pair.output,
            "bind-pair output index is out of range",
        )?;
        let destination = owner_for_port(
            input_owners,
            pair.input,
            "bind-pair input index is out of range",
        )?;
        let degree = indegree
            .get_mut(destination)
            .ok_or_else(|| format_error("coder dependency index is out of range"))?;
        *degree = degree
            .checked_add(1)
            .ok_or_else(|| format_error("coder dependency count overflows"))?;
        edges.push((source, destination));
    }

    let mut ready = Vec::new();
    try_reserve(&mut ready, coder_count)?;
    for (index, degree) in indegree.iter().enumerate() {
        if *degree == 0 {
            ready.push(index);
        }
    }
    let mut order = Vec::new();
    try_reserve(&mut order, coder_count)?;
    let mut cursor = 0_usize;
    while let Some(coder) = ready.get(cursor).copied() {
        cursor = cursor
            .checked_add(1)
            .ok_or_else(|| format_error("topological queue index overflows"))?;
        control.checkpoint(1)?;
        order.push(usize_to_u64(
            coder,
            "coder index is not representable as u64",
        )?);
        for (source, destination) in &edges {
            control.checkpoint(1)?;
            if *source != coder {
                continue;
            }
            let degree = indegree
                .get_mut(*destination)
                .ok_or_else(|| format_error("coder dependency index is out of range"))?;
            *degree = degree
                .checked_sub(1)
                .ok_or_else(|| format_error("coder dependency count underflows"))?;
            if *degree == 0 {
                ready.push(*destination);
            }
        }
    }
    if order.len() != coder_count {
        return Err(format_error("folder coder graph contains a cycle"));
    }
    Ok(order.into_boxed_slice())
}

#[allow(clippy::too_many_lines)]
pub(crate) fn validate_folder_graph(
    raw: &RawFolder<'_>,
    control: &mut ParseControl<'_>,
) -> Result<ValidatedGraph> {
    let port_count = raw
        .input_streams
        .checked_add(raw.output_streams)
        .ok_or_else(|| format_error("folder port count overflows"))?;
    control.checkpoint(port_count)?;
    let input_count = u64_to_usize(
        raw.input_streams,
        "folder input count is not representable on this platform",
    )?;
    let output_count = u64_to_usize(
        raw.output_streams,
        "folder output count is not representable on this platform",
    )?;
    let mut input_owners = Vec::new();
    try_reserve(&mut input_owners, input_count)?;
    let mut output_owners = Vec::new();
    try_reserve(&mut output_owners, output_count)?;
    for (coder_index, coder) in raw.coders.iter().enumerate() {
        let port_count = coder
            .input_streams
            .checked_add(coder.output_streams)
            .ok_or_else(|| format_error("coder port count overflows"))?;
        control.checkpoint(port_count)?;
        for _ in 0..coder.input_streams {
            input_owners.push(coder_index);
        }
        for _ in 0..coder.output_streams {
            output_owners.push(coder_index);
        }
    }
    if input_owners.len() != input_count || output_owners.len() != output_count {
        return Err(format_error("folder stream-owner totals are inconsistent"));
    }

    let mut input_used = false_vector(
        raw.input_streams,
        "folder input count is not representable on this platform",
    )?;
    let mut output_used = false_vector(
        raw.output_streams,
        "folder output count is not representable on this platform",
    )?;
    let mut bind_pairs = Vec::new();
    try_reserve(&mut bind_pairs, raw.bind_pairs.len())?;
    for pair in &raw.bind_pairs {
        bind_pairs.push(validate_bind_pair(pair, &mut input_used, &mut output_used)?);
    }

    let mut root_output = None;
    for (index, bound) in output_used.iter().enumerate() {
        if !bound {
            if root_output.is_some() {
                return Err(format_error("folder has multiple root output streams"));
            }
            root_output = Some(usize_to_u64(
                index,
                "root output index is not representable as u64",
            )?);
        }
    }
    let root_output_index =
        root_output.ok_or_else(|| format_error("folder has no root output stream"))?;

    let mut packed_indices = Vec::new();
    let packed_capacity = u64_to_usize(
        raw.packed_streams,
        "packed-input count is not representable on this platform",
    )?;
    try_reserve(&mut packed_indices, packed_capacity)?;
    match raw.packed_indices.as_deref() {
        Some(indices) => packed_indices.extend_from_slice(indices),
        None => {
            let index = input_used
                .iter()
                .position(|bound| !bound)
                .ok_or_else(|| format_error("folder has no unbound packed input"))?;
            packed_indices.push(usize_to_u64(
                index,
                "packed-input index is not representable as u64",
            )?);
        }
    }
    if packed_indices.len() != packed_capacity {
        return Err(format_error("folder packed-input count is inconsistent"));
    }
    let mut packed_used = false_vector(
        raw.input_streams,
        "folder input count is not representable on this platform",
    )?;
    for index in &packed_indices {
        let index = u64_to_usize(
            *index,
            "packed-input index is not representable on this platform",
        )?;
        let is_packed = packed_used
            .get_mut(index)
            .ok_or_else(|| format_error("packed-input index is out of range"))?;
        if *is_packed {
            return Err(format_error("packed-input index is duplicated"));
        }
        let is_bound = input_used
            .get(index)
            .copied()
            .ok_or_else(|| format_error("packed-input index is out of range"))?;
        if is_bound {
            return Err(format_error("packed-input index is already bound"));
        }
        *is_packed = true;
    }
    for (bound, packed) in input_used.iter().zip(&packed_used) {
        if *bound == *packed {
            return Err(format_error(
                "folder inputs are not partitioned into bound and packed streams",
            ));
        }
    }

    Ok(ValidatedGraph {
        bind_pairs: bind_pairs.into_boxed_slice(),
        packed_input_indices: packed_indices.into_boxed_slice(),
        root_output_index,
        topological_coder_order: topological_order(
            raw.coders.len(),
            &input_owners,
            &output_owners,
            &raw.bind_pairs,
            control,
        )?,
    })
}
