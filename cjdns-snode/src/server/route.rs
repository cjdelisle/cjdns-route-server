//! Route computation

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use thiserror::Error;

use cjdns_core::splice::{get_encoding_form, re_encode, splice};
use cjdns_core::{EncodingScheme, RoutingLabel};
use cjdns_keys::CJDNS_IP6;

use crate::pathsearch::{Dijkstra, GraphBuilder, GraphSolver};
use crate::server::nodes::{Node, Nodes};
use crate::server::Server;

use serde::Serialize;

pub struct Routing {
    last_rebuild: Instant,
    route_cache: HashMap<CacheKey, Option<Route>>,
    dijkstra: Option<Dijkstra<CJDNS_IP6, f64>>,
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
struct CacheKey(CJDNS_IP6, CJDNS_IP6);

#[derive(Clone, Serialize)]
pub struct Route {
    pub label: RoutingLabel<u64>,
    hops: Vec<Hop>,
    path: Vec<CJDNS_IP6>,
}

#[derive(Clone, Serialize)]
struct Hop {
    label: RoutingLabel<u64>,
    orig_label: RoutingLabel<u32>,
    scheme: Arc<EncodingScheme>,
    inverse_form_num: u8,
}

#[derive(PartialEq, Eq, Clone, Debug, Error)]
pub enum RoutingError {
    #[error("Can't build route - either start or end node is not specified")]
    NoInput,
    // #[error("Route not found between {0} and {1}")]
    // RouteNotFound(CJDNS_IP6, CJDNS_IP6),
    #[error("Empty path between {0} and {1}")]
    PathIsEmpty(CJDNS_IP6, CJDNS_IP6),
    #[error("RoutingLabel::try_new({0}) failed")]
    RoutingLabelTryNewFailed(u16),
    #[error("get_encoding_form failed: {0}")]
    GetEncodingFormFailed(String),
    #[error("re_encode failed: {0}")]
    ReEncodeFailed(String),
    #[error("No nodes.by_ip({0})")]
    NoNodeByIp(CJDNS_IP6),
    #[error("{0}.inward_links_by_ip ({1})")]
    NoInwardLinksByIp(&'static str, CJDNS_IP6),
    #[error("splice(&labels) failed: {0}")]
    Splice(String),
}

pub(super) fn get_route(server: Arc<Server>, src: Option<Arc<Node>>, dst: Option<Arc<Node>>) -> Result<Route, RoutingError> {
    if let (Some(src), Some(dst)) = (src, dst) {
        if src == dst {
            Ok(Route::identity())
        } else {
            let nodes = &server.nodes;
            let routing = &mut server.mut_state.lock().routing;
            get_route_impl(nodes, routing, src, dst, server.use_old_compute_routing_label_impl)
            // let error = RoutingError::RouteNotFound(src.ipv6.clone(), dst.ipv6.clone());
            // get_route_impl(nodes, routing, src, dst).ok_or(error)
        }
    } else {
        Err(RoutingError::NoInput)
    }
}

fn get_route_impl(nodes: &Nodes, routing: &mut Routing, src: Arc<Node>, dst: Arc<Node>, use_old_impl: bool) -> Result<Route, RoutingError> {
    let now = Instant::now();
    const REBUILD_INTERVAL: Duration = Duration::from_secs(3);
    if routing.last_rebuild + REBUILD_INTERVAL < now || routing.dijkstra.is_none() {
        routing.route_cache.clear();
        let d = build_node_graph(nodes);
        routing.dijkstra = Some(d);
        routing.last_rebuild = now;
    }

    let cache_key = CacheKey(dst.ipv6.clone(), src.ipv6.clone());
    if let Some(Some(cached_entry)) = routing.route_cache.get(&cache_key).cloned() {
        return Ok(cached_entry);
    }

    let route = compute_route(nodes, routing, src, dst, use_old_impl);

    routing.route_cache.insert(cache_key, route.as_ref().ok().cloned());

    route
}

fn build_node_graph(nodes: &Nodes) -> Dijkstra<CJDNS_IP6, f64> {
    let mut d = Dijkstra::new();

    for nip in nodes.all_ips() {
        let node = nodes.by_ip(&nip).unwrap();
        let links = node.inward_links_by_ip.lock();
        let mut l = HashMap::new();
        for (pip, peer_links) in links.iter() {
            if peer_links.is_empty() {
                continue; // Shouldn't happen but let's be safe
            }
            if let Some(reverse) = nodes.by_ip(pip) {
                if reverse.inward_links_by_ip.lock().get(&nip).is_none() {
                    continue;
                }
                let total_cmp = |a: &f64, b: &f64| {
                    // Replace with `f64::total_cmp` when it is stabilized
                    let mut a = a.to_bits() as i64;
                    let mut b = b.to_bits() as i64;
                    a ^= (((a >> 63) as u64) >> 1) as i64;
                    b ^= (((b >> 63) as u64) >> 1) as i64;
                    a.cmp(&b)
                };
                let max_value = peer_links
                    .iter()
                    .map(|link| link.mut_state.lock().value)
                    .max_by(total_cmp) // Replace with `f64::total_cmp` when it is stabilized (unstable as of Rust 1.46)
                    .expect("no links") // Safe because of the above `peer_links.is_empty()` check
                    ;
                let max_value = if max_value == 0.0 { 1e-20 } else { max_value };
                let min_cost = max_value.recip();
                l.insert(pip.clone(), min_cost);
            }
        }
        trace!("building dijkstra tree {} {:?}", nip, l);
        d.add_node(nip, l.into_iter());
    }

    d
}

fn compute_route(nodes: &Nodes, routing: &mut Routing, src: Arc<Node>, dst: Arc<Node>, use_old_impl: bool) -> Result<Route, RoutingError> {
    // We ask for the path in reverse because we build the graph in reverse.
    // Because nodes announce their own reachability instead of reachability of others.
    let path = {
        let dijkstra = routing.dijkstra.as_ref().expect("no path solver");
        dijkstra.reverse_path(&dst.ipv6, &src.ipv6)
    };

    if path.is_empty() {
        return Err(RoutingError::PathIsEmpty(src.ipv6.clone(), dst.ipv6.clone()));
    }

    let (label, hops) = compute_routing_label(nodes, &path, use_old_impl)?;

    let route = Route { label, hops, path };

    Ok(route)
}

fn compute_routing_label(nodes: &Nodes, rev_path: &[CJDNS_IP6], use_old_impl: bool) -> Result<(RoutingLabel<u64>, Vec<Hop>), RoutingError> {
    let (labels, hops) = {
        let mut last: Option<Arc<Node>> = None;
        let mut hops = Vec::new();
        let mut labels = Vec::new();
        let mut form_num = 0;

        for nip in rev_path.iter() {
            if let Some(node) = nodes.by_ip(nip) {
                if let Some(last) = last {
                    if use_old_impl {
                        if let Some(Some(link)) = node.inward_links_by_ip.lock().get(&last.ipv6).map(|ls| ls.get(0)) {
                            let mut label = RoutingLabel::try_new(link.label.bits() as u64)
                                .ok_or_else(|| RoutingError::RoutingLabelTryNewFailed(link.label.bits() as u16))?;
                            let (_, cur_form_num) =
                                get_encoding_form(label, &last.encoding_scheme).map_err(|err| RoutingError::GetEncodingFormFailed(err.to_string()))?;
                            if cur_form_num < form_num {
                                label = re_encode(label, &last.encoding_scheme, Some(form_num)).map_err(|err| RoutingError::ReEncodeFailed(err.to_string()))?;
                            }
                            labels.push(label);
                            let hop = Hop {
                                label: label.clone(),
                                orig_label: link.label.clone(),
                                scheme: last.encoding_scheme.clone(),
                                inverse_form_num: form_num,
                            };
                            hops.push(hop);
                            form_num = link.encoding_form_number;
                        } else {
                            return Err(RoutingError::NoInwardLinksByIp("node", last.ipv6.clone()));
                        }
                    } else {
                        if let Some(greta_opinion_link) = node.inward_links_by_ip.lock().get(&last.ipv6).and_then(|ls| ls.get(0)) {
                            if let Some(yury_opinion_link) = last.inward_links_by_ip.lock().get(&node.ipv6).and_then(|ls| ls.get(0)) {
                                // Yury sends message to Caleb via Greta
                                // last stand for yury
                                // node stands for greta
                                let label_yg_32 = RoutingLabel::try_new(yury_opinion_link.peer_num as u32)
                                    .ok_or_else(|| RoutingError::RoutingLabelTryNewFailed(yury_opinion_link.peer_num))?;
                                let mut label_yg = RoutingLabel::try_new(yury_opinion_link.peer_num as u64)
                                    .ok_or_else(|| RoutingError::RoutingLabelTryNewFailed(yury_opinion_link.peer_num))?;
                                let label_gy = RoutingLabel::try_new(greta_opinion_link.peer_num as u64)
                                    .ok_or_else(|| RoutingError::RoutingLabelTryNewFailed(greta_opinion_link.peer_num))?;
                                let (_, cur_form_num_yg) =
                                    get_encoding_form(label_yg, &node.encoding_scheme).map_err(|err| RoutingError::GetEncodingFormFailed(err.to_string()))?;
                                let (_, cur_form_num_gy) =
                                    get_encoding_form(label_gy, &last.encoding_scheme).map_err(|err| RoutingError::GetEncodingFormFailed(err.to_string()))?;
                                let label_yg_backup = label_yg_32;
                                if cur_form_num_yg < form_num {
                                    label_yg = re_encode(label_yg, &last.encoding_scheme, Some(form_num))
                                        .map_err(|err| RoutingError::ReEncodeFailed(err.to_string()))?;
                                }
                                labels.push(label_yg);
                                let hop = Hop {
                                    label: label_yg.clone(),
                                    orig_label: label_yg_backup.clone(),
                                    scheme: last.encoding_scheme.clone(),
                                    inverse_form_num: form_num,
                                };
                                hops.push(hop);
                                form_num = cur_form_num_gy;
                            } else {
                                return Err(RoutingError::NoInwardLinksByIp("last", node.ipv6.clone()));
                            }
                        } else {
                            return Err(RoutingError::NoInwardLinksByIp("node", last.ipv6.clone()));
                        }
                    }
                }
                last = Some(node);
            } else {
                return Err(RoutingError::NoNodeByIp((*nip).clone()));
            }
        }

        labels.push(RoutingLabel::self_reference());
        labels.reverse();

        (labels, hops)
    };

    let spliced = splice(&labels).map_err(|err| RoutingError::Splice(format!("{err}, label.len: {}", labels.len())))?;

    Ok((spliced, hops))
}

impl Route {
    fn identity() -> Self {
        Route {
            label: RoutingLabel::self_reference(),
            hops: Vec::new(),
            path: Vec::new(),
        }
    }
}

impl Routing {
    pub(super) fn new() -> Self {
        Routing {
            last_rebuild: Instant::now(),
            route_cache: HashMap::new(),
            dijkstra: None,
        }
    }
}
