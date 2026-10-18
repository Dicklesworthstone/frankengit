//! Bounded fan-out over the existing, independently fenced destination workers.
//!
//! These are operator-selected routes, not a new canonical subscription or
//! settlement mechanism. Each route retains the single-worker journal identity.

use super::*;
use std::collections::BTreeSet;

const MAX_ROUTES: usize = 32;
const USAGE: &str = "usage: fg webhook dispatch fanout <storage-root> <tenant-id> <repository-id> --trusted-local
  --route <registered-id>:<canonical-destination> [--route <id>:<destination> ...]
  --at-least-once [--max-total-deliveries <1..1000>]
  [--object-format sha1|sha256] [--max-deliveries <1..1000>]
  [--max-scan-entries <1..16384>] [--attempt-timeout-secs <1..60>]
  [--continuous --stop-file <path> [--poll-millis <100..60000>]]
  [--permissive-for-tests]

At most 32 explicit routes. Default: 64 total attempts and 16 per route per sweep.
Routes are ordered by registration ID and destination; continuous sweeps rotate
which route goes first. All journals are fenced before any send, and remain
locked until the controller exits. Each sweep reads one complete shared outbox
snapshot. Accepted observations survive a switch between single-route and fanout
workers. Delivery failures do not stop other routes; source, journal, or output
failures stop the controller. Cancellation is latched across every route.
A retry can duplicate an effect. Fan-out never settles canonical outbox state,
adds canonical subscriptions, or upgrades receiver idempotency. HTTPS is refused.
Use dispatch-status separately for each route's durable delivery observations.";

#[derive(Debug)]
struct FanoutOptions {
    routes: Vec<Options>,
    max_total_deliveries: usize,
}

fn parse(args: &[String]) -> Result<FanoutOptions, String> {
    if args.len() < 4
        || args.len() > 96
        || args.iter().any(|arg| arg.len() > 8192)
        || args.iter().map(String::len).sum::<usize>() > 32768
    {
        return Err(USAGE.into());
    }
    let mut common = args[..4].to_vec();
    let mut routes = BTreeSet::new();
    let mut max_total = None;
    let mut index = 4;
    while index < args.len() {
        let flag = args[index].as_str();
        index += 1;
        match flag {
            "--route" => {
                let value = args.get(index).ok_or("missing --route value")?;
                index += 1;
                let (id, destination) = value
                    .split_once(':')
                    .ok_or("route must be <registered-id>:<canonical-destination>")?;
                let id = number(id, 0, u64::MAX)?;
                let destination = AsciiSlug::try_new("fanout destination", destination.as_bytes())
                    .map_err(|error| error.to_string())?;
                if !routes.insert((id, destination)) {
                    return Err("duplicate fanout registration/destination route".into());
                }
                if routes.len() > MAX_ROUTES {
                    return Err("fanout supports at most 32 routes".into());
                }
            }
            "--max-total-deliveries" => {
                let value = args.get(index).ok_or("missing --max-total-deliveries value")?;
                index += 1;
                let value = number(value, 1, 1000)? as usize;
                if max_total.replace(value).is_some() {
                    return Err("duplicate --max-total-deliveries".into());
                }
            }
            "--id" | "--destination" => {
                return Err("fanout uses --route instead of --id or --destination".into());
            }
            "--at-least-once" | "--continuous" | "--permissive-for-tests" => {
                common.push(flag.to_owned());
            }
            "--object-format" | "--max-deliveries" | "--max-scan-entries"
            | "--attempt-timeout-secs" | "--stop-file" | "--poll-millis" => {
                let value = args.get(index).ok_or_else(|| format!("missing {flag} value"))?;
                index += 1;
                common.push(flag.to_owned());
                common.push(value.clone());
            }
            _ => return Err(format!("unknown fanout option {flag}")),
        }
    }
    if routes.is_empty() {
        return Err("fanout requires at least one explicit --route".into());
    }
    let mut options = Vec::with_capacity(routes.len());
    for (id, destination) in routes {
        let mut route_args = common.clone();
        route_args.extend([
            "--id".to_owned(),
            id.to_string(),
            "--destination".to_owned(),
            destination.as_str().to_owned(),
        ]);
        options.push(super::parse(&route_args)?);
    }
    Ok(FanoutOptions {
        routes: options,
        max_total_deliveries: max_total.unwrap_or(64),
    })
}

struct OwnedRoute {
    options: Options,
    binding: [u8; 32],
    journal: Journal,
}

pub(super) fn run(args: &[String]) -> Result<u8, String> {
    let mut output = std::io::stdout().lock();
    if args == ["--help"] {
        writeln!(output, "{USAGE}").map_err(|error| error.to_string())?;
        return Ok(0);
    }
    let options = parse(args)?;
    let stop_path = options.routes[0].stop_file.clone();
    let signals = TerminationSignals::install()
        .map_err(|error| format!("cannot own fanout shutdown: {error}"))?;
    execute(
        options,
        &|| Ok(signals.requested() || stop_file(stop_path.as_deref())?),
        &now_millis,
        &mut output,
    )
}

fn merge(total: &mut Summary, route: Summary) {
    total.considered += route.considered;
    total.attempts += route.attempts;
    total.accepted += route.accepted;
    total.rejected += route.rejected;
    total.unknown += route.unknown;
    total.pending += route.pending;
    total.filtered += route.filtered;
    total.claimed += route.claimed;
    total.stopped |= route.stopped;
}

/// Visit even budget-exhausted routes with zero send allowance: a retained
/// ambiguous outcome must still affect the aggregate exit status.
fn round(
    count: usize,
    first: usize,
    allowance: usize,
    stopped: &impl Fn() -> Result<bool, String>,
    mut visit: impl FnMut(usize, usize) -> Result<Summary, String>,
) -> Result<Summary, String> {
    let mut total = Summary::default();
    for offset in 0..count {
        if stopped()? {
            total.stopped = true;
            break;
        }
        let remaining = allowance - total.attempts;
        let route = visit((first + offset) % count, remaining)?;
        if route.attempts > remaining {
            return Err("fanout route exceeded the shared attempt allowance".into());
        }
        merge(&mut total, route);
        if total.stopped {
            break;
        }
    }
    total.stopped |= stopped()?;
    Ok(total)
}

fn execute(
    options: FanoutOptions,
    stop_signal: &impl Fn() -> Result<bool, String>,
    clock: &impl Fn() -> Result<u64, String>,
    output: &mut impl Write,
) -> Result<u8, String> {
    let latched = Cell::new(false);
    let stopped = || {
        if latched.get() {
            return Ok(true);
        }
        match stop_signal() {
            Ok(false) => Ok(false),
            result => {
                latched.set(true);
                result
            }
        }
    };
    let stop_record = "{\"type\":\"webhook_fanout_stopped\",\"schema_version\":1,\"stopped\":true,\"drained\":true,\"canonical_settled\":false}";
    if stopped()? {
        emit(output, stop_record)?;
        return Ok(1);
    }
    let first = options.routes.first().ok_or("fanout requires a route")?;
    let continuous = first.continuous;
    let poll = first.poll;
    let mut page = snapshot(first)?;
    let incarnation = page.incarnation;
    let mut routes = Vec::with_capacity(options.routes.len());
    // Acquire all route fences before the first send. Sorting at parse time
    // gives competing controllers a common acquisition order. A failure drops
    // every fence already acquired, without executing any route.
    for route in options.routes {
        if stopped()? {
            emit(output, stop_record)?;
            return Ok(1);
        }
        let (_, registration) = registration(&route)?;
        let binding = scope(&route, incarnation, &registration);
        let journal = Journal::open(
            &journal_path(&route),
            binding,
            registration.retry_schedule.max_attempts,
        )?;
        routes.push(OwnedRoute { options: route, binding, journal });
    }
    let mut first_route = 0;
    loop {
        if page.incarnation != incarnation {
            return Err("fanout repository incarnation changed; original journals retained".into());
        }
        let summary = round(
            routes.len(),
            first_route,
            options.max_total_deliveries,
            &stopped,
            |index, remaining| {
                let route = &mut routes[index];
                emit(output, &format!(
                    "{{\"type\":\"webhook_fanout_route\",\"schema_version\":1,\"webhook_id\":{},\"destination\":{},\"canonical_settled\":false}}",
                    route.options.id.0, quote(route.options.destination.as_str())))?;
                let per_route_limit = route.options.max_deliveries;
                route.options.max_deliveries = per_route_limit.min(remaining);
                let result = super::sweep(
                    &route.options,
                    &page,
                    route.binding,
                    &mut route.journal,
                    &stopped,
                    clock,
                    output,
                );
                route.options.max_deliveries = per_route_limit;
                let summary = result?;
                emit(output, &format!(
                    "{{\"type\":\"webhook_fanout_route_result\",\"schema_version\":1,\"webhook_id\":{},\"destination\":{},\"attempts\":{},\"exit_code\":{},\"canonical_settled\":false}}",
                    route.options.id.0, quote(route.options.destination.as_str()), summary.attempts, summary.exit_code()))?;
                Ok(summary)
            },
        )?;
        emit(output, &format!(
            "{{\"type\":\"webhook_fanout_sweep\",\"schema_version\":1,\"routes\":{},\"source_head\":{},\"attempts\":{},\"accepted\":{},\"rejected\":{},\"unknown\":{},\"pending\":{},\"filtered\":{},\"claimed_elsewhere\":{},\"stopped\":{},\"canonical_settled\":false}}",
            routes.len(), quote(&page.head.to_string()), summary.attempts, summary.accepted, summary.rejected,
            summary.unknown, summary.pending, summary.filtered, summary.claimed, summary.stopped))?;
        if !continuous || summary.stopped {
            return Ok(summary.exit_code());
        }
        first_route = (first_route + 1) % routes.len();
        let mut remaining = poll;
        while !remaining.is_zero() {
            if stopped()? {
                emit(output, stop_record)?;
                return Ok(summary.exit_code().max(1));
            }
            let interval = remaining.min(Duration::from_millis(100));
            std::thread::sleep(interval);
            remaining = remaining.saturating_sub(interval);
        }
        if stopped()? {
            emit(output, stop_record)?;
            return Ok(summary.exit_code().max(1));
        }
        page = snapshot(&routes[0].options)?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(extra: &[&str]) -> Vec<String> {
        let mut args = vec![
            "/operator-owned/node".to_owned(),
            TenantId::from_bytes([0xa1; 16]).to_string(),
            RepositoryId::from_bytes([0xa2; 16]).to_string(),
            "--trusted-local".to_owned(),
            "--at-least-once".to_owned(),
        ];
        args.extend(extra.iter().map(|arg| (*arg).to_owned()));
        args
    }

    #[test]
    fn routes_are_explicit_sorted_and_keep_single_worker_defaults() {
        let options = parse(&args(&["--route", "9:forge-events", "--route", "2:forge-events"])).unwrap();
        assert_eq!(options.routes.len(), 2);
        assert_eq!(options.routes[0].id.0, 2);
        assert_eq!(options.routes[1].id.0, 9);
        assert_eq!(options.max_total_deliveries, 64);
        assert_eq!(options.routes[0].max_deliveries, 16);
        assert_eq!(options.routes[0].max_scan, 16384);
    }

    #[test]
    fn duplicate_routes_and_single_destination_flags_are_rejected() {
        for extra in [
            vec!["--route", "7:forge-events", "--route", "7:forge-events"],
            vec!["--route", "7:forge-events", "--id", "8"],
            vec!["--route", "7:forge-events", "--destination", "other"],
            vec!["--route", "07:forge-events"],
            vec!["--route", "7:"],
            vec!["--route", "7"],
            vec![],
        ] {
            assert!(parse(&args(&extra)).is_err(), "{extra:?}");
        }
    }

    #[test]
    fn acknowledgement_and_continuous_stop_ownership_remain_mandatory() {
        let mut missing_ack = args(&["--route", "7:forge-events"]);
        missing_ack.retain(|arg| arg != "--at-least-once");
        assert!(parse(&missing_ack).is_err());
        assert!(parse(&args(&["--route", "7:forge-events", "--continuous"])).is_err());
        assert!(parse(&args(&["--route", "7:forge-events", "--stop-file", "/stop"])).is_err());
        let options = parse(&args(&[
            "--route", "7:forge-events", "--continuous", "--stop-file", "/stop",
            "--poll-millis", "100", "--max-total-deliveries", "1",
        ])).unwrap();
        assert!(options.routes[0].continuous);
        assert_eq!(options.max_total_deliveries, 1);
    }

    #[test]
    fn global_and_route_counts_are_bounded() {
        for value in ["0", "1001", "01", "+2"] {
            assert!(parse(&args(&["--route", "7:forge-events", "--max-total-deliveries", value])).is_err());
        }
        let mut many = args(&[]);
        for id in 0..MAX_ROUTES {
            many.extend(["--route".to_owned(), format!("{id}:forge-events")]);
        }
        assert_eq!(parse(&many).unwrap().routes.len(), MAX_ROUTES);
        many.extend(["--route".to_owned(), "32:forge-events".to_owned()]);
        assert!(parse(&many).is_err());
    }

    #[test]
    fn shared_budget_rotates_without_hiding_unknown_on_unsent_routes() {
        let mut order = Vec::new();
        let summary = round(3, 1, 1, &|| Ok(false), |index, remaining| {
            order.push((index, remaining));
            Ok(if remaining > 0 {
                Summary { attempts: 1, accepted: 1, ..Summary::default() }
            } else {
                Summary { unknown: 1, pending: 1, ..Summary::default() }
            })
        }).unwrap();
        assert_eq!(order, vec![(1, 1), (2, 0), (0, 0)]);
        assert_eq!(summary.attempts, 1);
        assert_eq!(summary.unknown, 2);
        assert_eq!(summary.exit_code(), 3);
    }

    #[test]
    fn rejected_route_does_not_starve_a_healthy_route() {
        let summary = round(2, 0, 2, &|| Ok(false), |index, _| {
            Ok(if index == 0 {
                Summary { attempts: 1, rejected: 1, ..Summary::default() }
            } else {
                Summary { attempts: 1, accepted: 1, ..Summary::default() }
            })
        }).unwrap();
        assert_eq!(summary.attempts, 2);
        assert_eq!(summary.accepted, 1);
        assert_eq!(summary.exit_code(), 2);
    }

    #[test]
    fn cancellation_and_invariant_failure_prevent_later_route_admission() {
        let stop = Cell::new(false);
        let mut visits = 0;
        let summary = round(3, 0, 3, &|| Ok(stop.get()), |_, _| {
            visits += 1;
            stop.set(true);
            Ok(Summary { attempts: 1, ..Summary::default() })
        }).unwrap();
        assert_eq!(visits, 1);
        assert!(summary.stopped);
        assert_eq!(summary.exit_code(), 1);
        let mut visits = 0;
        assert!(round(3, 0, 3, &|| Ok(false), |_, _| {
            visits += 1;
            Err("journal sync failed".into())
        }).is_err());
        assert_eq!(visits, 1);
    }
}

#[cfg(all(test, unix))]
mod integration;
