//! Router group builders extracted from `lib.rs`.

use axum::middleware as axum_mw;
use axum::routing::{delete, get, post, put};
use axum::Router;

use crate::middleware;
use crate::{
    routes_alerts, routes_analytics, routes_api_keys, routes_audit, routes_auth, routes_conflicts,
    routes_dns, routes_fingerprints, routes_firewall, routes_geo, routes_import, routes_ldap,
    routes_map, routes_notifications, routes_proxy, routes_report_schedules, routes_retention,
    routes_search, routes_security, routes_siem, routes_sse, routes_subnets, routes_switches, routes_tags, routes_timeline,
    routes_totp, routes_users, routes_v1, AppState,
};

/// Builds routes for auth endpoints (public + viewer-protected).
///
/// Parameters: `state` - shared application state.
/// Returns: grouped auth router.
pub fn auth_routes(state: AppState) -> Router<AppState> {
    let login_route = Router::new()
        .route("/api/auth/login", post(routes_auth::login))
        .layer(axum_mw::from_fn_with_state(
            state.clone(),
            crate::login_rate_limit,
        ));
    let public_auth = Router::new()
        .route("/api/auth/refresh", post(routes_auth::refresh))
        .merge(login_route);
    let protected_auth = Router::new()
        .route("/api/auth/totp/setup", post(routes_totp::setup))
        .route("/api/auth/totp/verify", post(routes_totp::verify))
        .route("/api/auth/totp/disable", post(routes_totp::disable))
        .route("/api/auth/totp/status", get(routes_totp::status))
        .route(
            "/api/auth/totp/backup-codes",
            post(routes_totp::regenerate_backup_codes),
        )
        .route("/api/auth/me", get(routes_auth::me))
        .route("/api/auth/sessions", get(routes_auth::list_sessions))
        .route("/api/auth/logout", post(routes_auth::logout))
        .route("/api/auth/logout-all", post(routes_auth::logout_all))
        .route(
            "/api/auth/change-password",
            post(routes_auth::change_password),
        )
        .layer(axum_mw::from_fn_with_state(
            state,
            middleware::require_viewer_layer,
        ));
    Router::new().merge(public_auth).merge(protected_auth)
}

/// Builds grouped v1 API routes (viewer-protected unless public health).
///
/// Parameters: `state` - shared application state.
/// Returns: grouped v1 router.
pub fn v1_routes(state: AppState) -> Router<AppState> {
    Router::new()
        .route("/api/v1/mappings", get(routes_v1::api_v1_mappings))
        .route("/api/v1/events", get(routes_v1::api_v1_events))
        .route("/api/v1/stats", get(routes_v1::api_v1_stats))
        .route("/lookup/{ip}", get(routes_v1::lookup))
        .route("/lookup/:ip", get(routes_v1::lookup))
        .route("/api/recent", get(routes_v1::recent))
        .route(
            "/api/v1/admin/adapters",
            get(routes_proxy::proxy_admin_adapters),
        )
        .route("/api/v1/admin/agents", get(routes_proxy::proxy_admin_agents))
        .route(
            "/api/v1/admin/runtime-config",
            get(routes_proxy::proxy_admin_runtime_config),
        )
        .layer(axum_mw::from_fn_with_state(
            state,
            middleware::require_viewer_layer,
        ))
}

/// Builds grouped v2 routes (viewer + operator subsets).
///
/// Parameters: `state` - shared application state.
/// Returns: grouped v2 router.
pub fn v2_routes(state: AppState) -> Router<AppState> {
    let viewer_routes = Router::new()
        .route("/api/v2/search", get(routes_search::search))
        .route(
            "/api/v2/export/mappings",
            get(routes_search::export_mappings),
        )
        .route("/api/v2/export/events", get(routes_search::export_events))
        .route(
            "/api/v2/timeline/ip/{ip}",
            get(routes_timeline::timeline_ip),
        )
        .route(
            "/api/v2/timeline/user/{user}",
            get(routes_timeline::timeline_user),
        )
        .route(
            "/api/v2/timeline/mac/{mac}",
            get(routes_timeline::timeline_mac),
        )
        .route("/api/v2/conflicts", get(routes_conflicts::list_conflicts))
        .route(
            "/api/v2/conflicts/stats",
            get(routes_conflicts::conflict_stats),
        )
        .route("/api/v2/subnets", get(routes_subnets::list_subnets))
        .route("/api/v2/subnets/stats", get(routes_subnets::subnet_stats))
        .route(
            "/api/v2/subnets/{id}/mappings",
            get(routes_subnets::subnet_mappings),
        )
        .route(
            "/api/v2/subnets/:id/mappings",
            get(routes_subnets::subnet_mappings),
        )
        .route("/api/v2/switches", get(routes_switches::list_switches))
        .route("/api/v2/switches/stats", get(routes_switches::switch_stats))
        .route("/api/v2/switches/{id}", get(routes_switches::get_switch))
        .route("/api/v2/switches/:id", get(routes_switches::get_switch))
        .route(
            "/api/v2/switch-ports",
            get(routes_switches::list_port_mappings),
        )
        .route(
            "/api/v2/switch-ports/by-mac/{mac}",
            get(routes_switches::port_by_mac),
        )
        .route("/api/v2/dns", get(routes_dns::list_dns))
        .route("/api/v2/dns/stats", get(routes_dns::dns_stats))
        .route("/api/v2/dns/{ip}", get(routes_dns::dns_by_ip))
        .route("/api/v2/dns/:ip", get(routes_dns::dns_by_ip))
        .route("/api/v2/geo/stats", get(routes_geo::stats))
        .route("/api/v2/geo/{ip}", get(routes_geo::lookup))
        .route("/api/v2/geo/:ip", get(routes_geo::lookup))
        .route("/api/v2/tags", get(routes_tags::list_tags))
        .route("/api/v2/tags/ip/{ip}", get(routes_tags::tags_for_ip))
        .route("/api/v2/tags/ip/:ip", get(routes_tags::tags_for_ip))
        .route("/api/v2/tags/search", get(routes_tags::search_by_tag))
        .route(
            "/api/v2/subnets/discovered",
            get(routes_subnets::list_discovered_subnets),
        )
        .route("/api/v2/siem/stats", get(routes_siem::siem_stats))
        .route("/api/v2/siem/targets", get(routes_siem::list_targets))
        .route("/api/v2/siem/targets/{id}", get(routes_siem::get_target))
        .route("/api/v2/siem/targets/:id", get(routes_siem::get_target))
        .route("/api/v2/ldap/groups", get(routes_ldap::list_groups))
        .route(
            "/api/v2/ldap/groups/{group}/members",
            get(routes_ldap::group_members),
        )
        .route(
            "/api/v2/ldap/groups/:group/members",
            get(routes_ldap::group_members),
        )
        .route(
            "/api/v2/ldap/users/{username}/groups",
            get(routes_ldap::user_groups),
        )
        .route(
            "/api/v2/ldap/users/:username/groups",
            get(routes_ldap::user_groups),
        )
        .route(
            "/api/v2/firewall/stats",
            get(routes_firewall::firewall_stats),
        )
        .route(
            "/api/v2/firewall/targets",
            get(routes_firewall::list_targets),
        )
        .route(
            "/api/v2/firewall/targets/{id}/history",
            get(routes_firewall::target_history),
        )
        .route(
            "/api/v2/firewall/targets/:id/history",
            get(routes_firewall::target_history),
        )
        .route(
            "/api/v2/firewall/targets/{id}",
            get(routes_firewall::get_target),
        )
        .route(
            "/api/v2/firewall/targets/:id",
            get(routes_firewall::get_target),
        )
        .route(
            "/api/v2/fingerprints",
            get(routes_fingerprints::list_fingerprints),
        )
        .route(
            "/api/v2/fingerprints/stats",
            get(routes_fingerprints::fingerprint_stats),
        )
        .route(
            "/api/v2/fingerprints/observations",
            get(routes_fingerprints::list_observations),
        )
        .route("/api/v2/alerts/history", get(routes_alerts::alert_history))
        .route("/api/v2/alerts/stats", get(routes_alerts::alert_stats))
        .route("/api/v2/analytics/trends", get(routes_analytics::trends))
        .route("/api/v2/analytics/top", get(routes_analytics::top_n))
        .route(
            "/api/v2/analytics/sources",
            get(routes_analytics::source_distribution),
        )
        .route(
            "/api/v2/analytics/compliance",
            get(routes_analytics::compliance),
        )
        .route(
            "/api/v2/analytics/reports",
            get(routes_analytics::list_reports),
        )
        .route(
            "/api/v2/analytics/reports/{id}",
            get(routes_analytics::get_report),
        )
        .route(
            "/api/v2/analytics/reports/:id",
            get(routes_analytics::get_report),
        )
        .route("/api/v2/map/topology", get(routes_map::topology))
        .route("/api/v2/map/flows", get(routes_map::flows))
        .route("/api/v2/events/stream", get(routes_sse::event_stream))
        .layer(axum_mw::from_fn_with_state(
            state.clone(),
            middleware::require_viewer_layer,
        ));
    let operator_routes = Router::new()
        .route("/api/v1/mappings", post(routes_proxy::proxy_post_mapping))
        .route(
            "/api/v1/mappings/{ip}",
            delete(routes_proxy::proxy_delete_mapping),
        )
        .route("/api/auth/sessions/{id}", delete(routes_auth::revoke_session))
        .route(
            "/api/v2/conflicts/{id}/resolve",
            post(routes_conflicts::resolve_conflict),
        )
        .route("/api/v2/tags", post(routes_tags::create_tag))
        .route("/api/v2/tags/{id}", delete(routes_tags::delete_tag))
        .route("/api/v2/tags/:id", delete(routes_tags::delete_tag))
        .route(
            "/api/v2/subnets/promote",
            post(routes_subnets::promote_discovered_subnet),
        )
        .layer(axum_mw::from_fn_with_state(
            state,
            middleware::require_operator_layer,
        ));
    Router::new().merge(viewer_routes).merge(operator_routes)
}

/// Builds grouped admin routes (v1 admin + v2 mutable/admin actions).
///
/// Parameters: `state` - shared application state.
/// Returns: grouped admin router.
pub fn admin_routes(state: AppState) -> Router<AppState> {
    Router::new()
        .route(
            "/api/v1/admin/config/ttl",
            get(routes_proxy::proxy_get_ttl).put(routes_proxy::proxy_put_ttl),
        )
        .route(
            "/api/v1/admin/config/source-priority",
            get(routes_proxy::proxy_get_source_priority).put(routes_proxy::proxy_put_source_priority),
        )
        .route(
            "/api/v1/admin/config/sycope",
            get(routes_proxy::proxy_get_sycope).put(routes_proxy::proxy_put_sycope),
        )
        .route(
            "/api/v1/users",
            get(routes_users::list_users).post(routes_users::create_user),
        )
        .route(
            "/api/v1/users/{id}",
            get(routes_users::get_user).delete(routes_users::delete_user),
        )
        .route("/api/v1/users/{id}/role", put(routes_users::change_role))
        .route(
            "/api/v1/users/{id}/reset-password",
            post(routes_users::reset_password),
        )
        .route("/api/v1/users/{id}/unlock", post(routes_users::unlock_account))
        .route("/api/v1/users/{id}/totp", delete(routes_users::disable_user_totp))
        .route(
            "/api/v1/api-keys",
            get(routes_api_keys::list_keys).post(routes_api_keys::create_key),
        )
        .route("/api/v1/api-keys/{id}", delete(routes_api_keys::revoke_key))
        .route(
            "/api/v1/audit-logs",
            get(routes_audit::list_audit_logs),
        )
        .route(
            "/api/v1/audit-logs/stats",
            get(routes_audit::audit_stats),
        )
        .route(
            "/api/v2/admin/security/password-policy",
            get(routes_security::get_password_policy).put(routes_security::update_password_policy),
        )
        .route(
            "/api/v2/admin/security/sessions",
            get(routes_security::list_all_sessions),
        )
        .route(
            "/api/v2/admin/security/sessions/{id}",
            delete(routes_security::revoke_any_session),
        )
        .route(
            "/api/v2/admin/security/sessions/:id",
            delete(routes_security::revoke_any_session),
        )
        .route(
            "/api/v2/admin/security/totp-requirement",
            put(routes_security::set_totp_requirement),
        )
        .route(
            "/api/v2/alerts/rules",
            get(routes_alerts::list_rules).post(routes_alerts::create_rule),
        )
        .route(
            "/api/v2/alerts/rules/{id}",
            put(routes_alerts::update_rule).delete(routes_alerts::delete_rule),
        )
        .route("/api/v2/subnets", post(routes_subnets::create_subnet))
        .route(
            "/api/v2/subnets/{id}",
            put(routes_subnets::update_subnet).delete(routes_subnets::delete_subnet),
        )
        .route(
            "/api/v2/subnets/:id",
            put(routes_subnets::update_subnet).delete(routes_subnets::delete_subnet),
        )
        .route("/api/v2/switches", post(routes_switches::create_switch))
        .route(
            "/api/v2/switches/{id}",
            put(routes_switches::update_switch).delete(routes_switches::delete_switch),
        )
        .route(
            "/api/v2/switches/:id",
            put(routes_switches::update_switch).delete(routes_switches::delete_switch),
        )
        .route("/api/v2/switches/{id}/poll", post(routes_switches::force_poll))
        .route("/api/v2/switches/:id/poll", post(routes_switches::force_poll))
        .route("/api/v2/dns/{ip}", delete(routes_dns::delete_dns_ip))
        .route("/api/v2/dns/:ip", delete(routes_dns::delete_dns_ip))
        .route("/api/v2/dns/flush", post(routes_dns::flush_dns_cache))
        .route("/api/v2/ldap/config", get(routes_ldap::get_ldap_config))
        .route("/api/v2/ldap/config", put(routes_ldap::update_ldap_config))
        .route("/api/v2/ldap/sync", post(routes_ldap::force_ldap_sync))
        .route("/api/v2/import/events", post(routes_import::import_events))
        .route(
            "/api/v2/admin/retention",
            get(routes_retention::list_policies),
        )
        .route(
            "/api/v2/admin/retention/{table_name}",
            put(routes_retention::update_policy),
        )
        .route(
            "/api/v2/admin/retention/:table_name",
            put(routes_retention::update_policy),
        )
        .route(
            "/api/v2/admin/retention/run",
            post(routes_retention::run_now),
        )
        .route(
            "/api/v2/admin/retention/stats",
            get(routes_retention::stats),
        )
        .route("/api/v2/geo/refresh", post(routes_geo::refresh))
        .route(
            "/api/v2/subnets/discovered/{id}",
            delete(routes_subnets::dismiss_discovered_subnet),
        )
        .route(
            "/api/v2/subnets/discovered/:id",
            delete(routes_subnets::dismiss_discovered_subnet),
        )
        .route(
            "/api/v2/notifications/channels",
            get(routes_notifications::list_channels).post(routes_notifications::create_channel),
        )
        .route(
            "/api/v2/notifications/channels/{id}",
            get(routes_notifications::get_channel)
                .put(routes_notifications::update_channel)
                .delete(routes_notifications::delete_channel),
        )
        .route(
            "/api/v2/notifications/channels/:id",
            get(routes_notifications::get_channel)
                .put(routes_notifications::update_channel)
                .delete(routes_notifications::delete_channel),
        )
        .route(
            "/api/v2/notifications/channels/{id}/test",
            post(routes_notifications::test_channel),
        )
        .route(
            "/api/v2/notifications/channels/:id/test",
            post(routes_notifications::test_channel),
        )
        .route(
            "/api/v2/notifications/channels/{id}/deliveries",
            get(routes_notifications::channel_deliveries),
        )
        .route(
            "/api/v2/notifications/channels/:id/deliveries",
            get(routes_notifications::channel_deliveries),
        )
        .route("/api/v2/siem/targets", post(routes_siem::create_target))
        .route(
            "/api/v2/siem/targets/{id}",
            put(routes_siem::update_target).delete(routes_siem::delete_target),
        )
        .route(
            "/api/v2/siem/targets/:id",
            put(routes_siem::update_target).delete(routes_siem::delete_target),
        )
        .route(
            "/api/v2/firewall/targets",
            post(routes_firewall::create_target),
        )
        .route(
            "/api/v2/firewall/targets/{id}/push",
            post(routes_firewall::force_push),
        )
        .route(
            "/api/v2/firewall/targets/:id/push",
            post(routes_firewall::force_push),
        )
        .route(
            "/api/v2/firewall/targets/{id}/test",
            post(routes_firewall::test_target),
        )
        .route(
            "/api/v2/firewall/targets/:id/test",
            post(routes_firewall::test_target),
        )
        .route(
            "/api/v2/firewall/targets/{id}",
            put(routes_firewall::update_target).delete(routes_firewall::delete_target),
        )
        .route(
            "/api/v2/firewall/targets/:id",
            put(routes_firewall::update_target).delete(routes_firewall::delete_target),
        )
        .route(
            "/api/v2/fingerprints",
            post(routes_fingerprints::create_fingerprint),
        )
        .route(
            "/api/v2/fingerprints/backfill",
            post(routes_fingerprints::backfill),
        )
        .route(
            "/api/v2/fingerprints/{id}",
            delete(routes_fingerprints::delete_fingerprint),
        )
        .route(
            "/api/v2/fingerprints/:id",
            delete(routes_fingerprints::delete_fingerprint),
        )
        .route(
            "/api/v2/analytics/reports/generate",
            post(routes_analytics::generate_report),
        )
        .route(
            "/api/v2/reports/schedules",
            get(routes_report_schedules::list_schedules)
                .post(routes_report_schedules::create_schedule),
        )
        .route(
            "/api/v2/reports/schedules/{id}",
            put(routes_report_schedules::update_schedule)
                .delete(routes_report_schedules::delete_schedule),
        )
        .route(
            "/api/v2/reports/schedules/:id",
            put(routes_report_schedules::update_schedule)
                .delete(routes_report_schedules::delete_schedule),
        )
        .route(
            "/api/v2/reports/schedules/{id}/send-now",
            post(routes_report_schedules::send_now),
        )
        .route(
            "/api/v2/reports/schedules/:id/send-now",
            post(routes_report_schedules::send_now),
        )
        .layer(axum_mw::from_fn_with_state(
            state,
            middleware::require_admin_layer,
        ))
}

/// Builds public system routes.
///
/// Parameters: none.
/// Returns: public system router.
pub fn system_routes() -> Router<AppState> {
    Router::new()
        .route("/health", get(routes_v1::health))
        .route("/metrics", get(routes_proxy::proxy_metrics))
}
