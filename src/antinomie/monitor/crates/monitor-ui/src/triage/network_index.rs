// SPDX-License-Identifier: MIT
//! Aggregate owned capture segments before applying filters, sorting and pages.
use super::*;

pub(super) fn collect(
    directory: &Path,
    path: &Path,
    open: bool,
    cancel: &Arc<AtomicBool>,
    request: &ScanRequest,
    observe: &mut impl FnMut(&Path, bool, &[Cell], &str, &str) -> Result<(), String>,
) -> Result<PacketIndex, String> {
    let mut paths = vec![path.to_path_buf()];
    if request.owned_pcap {
        let artifacts = antinomie_monitor_core::RunArtifacts::load(directory)?
            .ok_or("Owned capture manifest is unavailable")?;
        if !request.identity.as_ref().is_some_and(|(vm, boot, run)| {
            *vm == artifacts.vm_id && *boot == artifacts.boot_id && *run == artifacts.run_id
        }) {
            return Err("Network artifact identity mismatch".into());
        }
        paths = artifacts.network_captures;
    }
    let mut seen = std::collections::BTreeSet::new();
    paths.retain(|path| seen.insert(path.clone()));
    let mut warnings = Vec::new();
    if paths.len() > 128 {
        paths.truncate(128);
        warnings.push("Only the first 128 capture segments fit the analysis budget".into());
    }
    let mut http_page = sorting::Page::new(request, 3, cancel);
    let mut dns_page = sorting::Page::new(request, 4, cancel);
    let http_query = query::compile_table(&request.filters[3], HTTP_FIELDS);
    let dns_query = query::compile_table(&request.filters[4], DNS_FIELDS);
    let mut inventory = network::Inventory::default();
    let mut inner = request.clone();
    inner.offsets = [0; 8];
    inner.filters = Default::default();
    inner.sorts = Default::default();
    let mut coverage = Vec::new();
    let mut succeeded = 0;
    let mut total_size = 0u64;
    let mut frames = 0u64;
    for path in &paths {
        if cancel.load(Ordering::Relaxed) {
            return Err("cancelled".into());
        }
        match std::fs::metadata(path) {
            Ok(metadata) if total_size.saturating_add(metadata.len()) <= 2 * 1024 * 1024 * 1024 => {
                total_size += metadata.len()
            }
            Ok(_) => {
                warnings.push("Network input reached the 2 GiB analysis budget".into());
                break;
            }
            Err(error) => {
                warnings.push(format!("{}: {error}", path.display()));
                continue;
            }
        }
        let result = scan_pcap_query_observed(
            path,
            open,
            cancel,
            &inner,
            &mut inventory,
            &mut |http, row, destination, port| {
                observe(path, http, row, destination, port)?;
                if http && http_query.keep_table(&row[0].values) {
                    http_page.push(row.to_vec())?;
                }
                if !http && dns_query.keep_table(&row[0].values) {
                    dns_page.push(row.to_vec())?;
                }
                Ok(())
            },
        );
        match result {
            Ok(index) => {
                frames += index.counts.map_or(0, |counts| counts.0);
                succeeded += 1;
                coverage.push(index.coverage);
                if let Some(warning) = index.network_warning {
                    warnings.push(warning);
                }
            }
            Err(error) if cancel.load(Ordering::Relaxed) => return Err(error),
            Err(error) => warnings.push(format!("{}: {error}", path.display())),
        }
    }
    if succeeded == 0 {
        return Err(format!(
            "No capture segment could be fully indexed: {}",
            warnings.join("; ")
        ));
    }
    if paths.len() > 1 {
        warnings.push("Streams are correlated within each capture segment; snapshot boundaries interrupt reassembly.".into());
    }
    let (http, http_omitted, _) = http_page.finish()?;
    let (dns, dns_omitted, _) = dns_page.finish()?;
    let (ips, hosts) = inventory.rows();
    let counts = Some((frames, ips.len() as u64, hosts.len() as u64));
    let mut inventory_pages = Vec::new();
    for (slot, rows, fields) in [
        (6, ips, network::IP_FIELDS),
        (7, hosts, network::HOST_FIELDS),
    ] {
        let query = query::compile_table(&request.filters[slot], fields);
        let mut page = sorting::Page::new(request, slot, cancel);
        for row in rows {
            if query.keep_table(&row[0].values) {
                page.push(row)?;
            }
        }
        inventory_pages.push(page.finish()?);
    }
    let (ips, ips_omitted, _) = inventory_pages.remove(0);
    let (hosts, hosts_omitted, _) = inventory_pages.remove(0);
    Ok(PacketIndex {
        counts,
        coverage: coverage.join(". "),
        http,
        http_omitted,
        dns,
        dns_omitted,
        ips,
        ips_omitted,
        hosts,
        hosts_omitted,
        network_warning: (!warnings.is_empty()).then(|| warnings.join("; ")),
    })
}
