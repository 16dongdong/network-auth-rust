use chrono::{Local, NaiveDate, NaiveDateTime, NaiveTime};
use serde_json::{Value, json};

use crate::{
    error::AppError,
    repository::{
        AppActivityCleanup, MessageActionEffect, MessageActionRow, MessageAdminAction,
        MessageAuditRow, MessageFilters, MessageRow, MessageStatusUpdate,
    },
};

use super::{format_datetime, ids, int_range, payload_string, positive_id, safe_text};

const MESSAGE_STATUSES: &[&str] = &["unread", "read", "handling", "handled", "archived"];
const SECURITY_ACTIONS: &[&str] = &[
    "record_only",
    "manual_review",
    "kick_session",
    "disable_device",
    "disable_card",
];
const SECURITY_RISK_LEVELS: &[&str] = &["low", "medium", "high", "critical"];
const SECURITY_EVENT_TYPES: &[&str] = &[
    "debugger_detected",
    "tracer_detected",
    "hook_detected",
    "instrumentation_detected",
    "module_tampered",
    "signature_mismatch",
    "emulator_detected",
    "root_detected",
    "attestation_failed",
    "policy_violation",
];

pub fn message_filters(payload: &Value) -> Result<MessageFilters, AppError> {
    let page = int_range(payload.get("page"), 1, 1_000_000, 1);
    let limit = int_range(payload.get("limit"), 1, 100, 20);
    Ok(MessageFilters {
        status: optional_message_status(&payload_string(payload, "status"))?,
        action: optional_security_action(&payload_string(payload, "action"))?,
        risk_level: optional_risk_level(&payload_string(payload, "risk_level"))?,
        event_type: optional_security_event_type(&payload_string(payload, "event_type"))?,
        card_fingerprint: safe_text(&payload_string(payload, "card_fingerprint"), 32)?,
        install_id: safe_text(&payload_string(payload, "install_id"), 80)?,
        ip: safe_text(&payload_string(payload, "ip"), 45)?,
        start: date_boundary(&payload_string(payload, "start"), false)?,
        end: date_boundary(&payload_string(payload, "end"), true)?,
        limit,
        offset: (page - 1) * limit,
    })
}

pub fn message_id(value: Option<&Value>) -> Result<u64, AppError> {
    positive_id(value)
}

pub fn message_ids(payload: &Value) -> Result<Vec<u64>, AppError> {
    ids(payload.get("message_ids"))
}

pub fn status_update(
    payload: &Value,
    status: &str,
    action: &str,
    actor_name: &str,
    ip: &str,
) -> Result<MessageStatusUpdate, AppError> {
    let now = Local::now().naive_local();
    let status = message_status(status)?;
    Ok(MessageStatusUpdate {
        read_at: (status == "read").then_some(now),
        handled_by: if status == "handled" {
            actor_name.to_string()
        } else {
            String::new()
        },
        handled_at: (status == "handled").then_some(now),
        archived_at: (status == "archived").then_some(now),
        action: action.to_string(),
        actor_name: actor_name.to_string(),
        remark: safe_text(&payload_string(payload, "remark"), 255)?,
        ip: ip.to_string(),
        status,
    })
}

pub fn admin_action(
    payload: &Value,
    actor_name: &str,
    ip: &str,
) -> Result<MessageAdminAction, AppError> {
    let action = security_action(&payload_string(payload, "action"))?;
    let message_id = message_id(payload.get("message_id"))?;
    Ok(MessageAdminAction {
        audit_message: format!("消息#{message_id} 人工处置：{action}"),
        action,
        actor_name: actor_name.to_string(),
        remark: safe_text(&payload_string(payload, "remark"), 255)?,
        ip: ip.to_string(),
    })
}

pub fn message_view(message: &MessageRow) -> Value {
    json!({
        "id": message.id,
        "event_id": message.event_id,
        "event_type": message.event_type,
        "risk_level": normalized_risk_level(message),
        "confidence": message.confidence,
        "requested_action": message.requested_action,
        "action": normalized_security_action(&message.action),
        "action_source": message.action_source,
        "status": normalized_message_status(&message.status),
        "title": message.title,
        "summary": message.summary,
        "risk_score": message.risk_score,
        "card_fingerprint": message.card_fingerprint,
        "install_id": message.install_id,
        "ip": message.ip,
        "platform": message.platform,
        "occurred_at": format_datetime(message.occurred_at),
        "created_at": message.created_at.format("%Y-%m-%d %H:%M:%S").to_string(),
    })
}

pub fn message_detail_view(
    message: &MessageRow,
    actions: &[MessageActionRow],
    audits: &[MessageAuditRow],
) -> Value {
    let mut view = message_view(message);
    let Value::Object(ref mut object) = view else {
        return view;
    };
    object.insert("message_id".to_string(), json!(message.id));
    object.insert(
        "report_id".to_string(),
        json!(message.report_id.unwrap_or(0)),
    );
    object.insert(
        "session_id".to_string(),
        json!(message.session_id.unwrap_or(0)),
    );
    object.insert(
        "device_id".to_string(),
        json!(message.device_id.unwrap_or(0)),
    );
    object.insert("card_id".to_string(), json!(message.card_id.unwrap_or(0)));
    object.insert("action_reason".to_string(), json!(message.action_reason));
    object.insert("message".to_string(), json!(message.report_message));
    object.insert("evidence".to_string(), json_array(&message.evidence_json));
    object.insert(
        "attestation".to_string(),
        json_array(&message.attestation_json),
    );
    object.insert("sdk_version".to_string(), json!(message.sdk_version));
    object.insert(
        "detector_version".to_string(),
        json!(message.detector_version),
    );
    object.insert(
        "read_at".to_string(),
        json!(format_datetime(message.read_at)),
    );
    object.insert("handled_by".to_string(), json!(message.handled_by));
    object.insert(
        "handled_at".to_string(),
        json!(format_datetime(message.handled_at)),
    );
    object.insert(
        "archived_at".to_string(),
        json!(format_datetime(message.archived_at)),
    );
    object.insert(
        "actions".to_string(),
        json!(actions.iter().map(message_action_view).collect::<Vec<_>>()),
    );
    object.insert(
        "audits".to_string(),
        json!(audits.iter().map(message_audit_view).collect::<Vec<_>>()),
    );
    view
}

pub fn activity_cleanup_view(cleanup: AppActivityCleanup, app_code: &str) -> Value {
    json!({
        "deleted_message_actions": cleanup.deleted_message_actions,
        "deleted_messages": cleanup.deleted_messages,
        "deleted_security_reports": cleanup.deleted_security_reports,
        "deleted_audit_logs": cleanup.deleted_audit_logs,
        "app_code": app_code,
    })
}

pub fn action_effect_view(effect: MessageActionEffect) -> Value {
    json!({
        "result": effect.result,
        "revoked_sessions": effect.revoked_sessions,
        "device_disabled": effect.device_disabled,
        "card_disabled": effect.card_disabled,
        "handled": true,
    })
}

fn message_action_view(action: &MessageActionRow) -> Value {
    json!({
        "id": action.id,
        "action": action.action,
        "actor_type": action.actor_type,
        "actor_name": action.actor_name,
        "result": action.result,
        "remark": action.remark,
        "ip": action.ip,
        "created_at": action.created_at.format("%Y-%m-%d %H:%M:%S").to_string(),
    })
}

fn message_audit_view(audit: &MessageAuditRow) -> Value {
    json!({
        "id": audit.id,
        "action": audit.action,
        "message": audit.message,
        "ip": audit.ip,
        "created_at": audit.created_at.format("%Y-%m-%d %H:%M:%S").to_string(),
    })
}

fn message_status(value: &str) -> Result<String, AppError> {
    enum_value(value, MESSAGE_STATUSES, AppError::InvalidMessageStatus)
}

fn optional_message_status(value: &str) -> Result<String, AppError> {
    optional_enum_value(value, message_status)
}

pub(super) fn security_action(value: &str) -> Result<String, AppError> {
    enum_value(value, SECURITY_ACTIONS, AppError::InvalidSecurityAction)
}

fn optional_security_action(value: &str) -> Result<String, AppError> {
    optional_enum_value(value, security_action)
}

fn risk_level(value: &str) -> Result<String, AppError> {
    enum_value(
        value,
        SECURITY_RISK_LEVELS,
        AppError::InvalidSecurityRiskLevel,
    )
}

fn optional_risk_level(value: &str) -> Result<String, AppError> {
    optional_enum_value(value, risk_level)
}

pub(super) fn security_event_type(value: &str) -> Result<String, AppError> {
    enum_value(
        value,
        SECURITY_EVENT_TYPES,
        AppError::InvalidSecurityEventType,
    )
}

fn optional_security_event_type(value: &str) -> Result<String, AppError> {
    optional_enum_value(value, security_event_type)
}

fn enum_value(value: &str, allowed: &[&str], error: AppError) -> Result<String, AppError> {
    let normalized = value.trim().to_ascii_lowercase();
    if allowed.contains(&normalized.as_str()) {
        return Ok(normalized);
    }
    Err(error)
}

fn optional_enum_value(
    value: &str,
    validator: fn(&str) -> Result<String, AppError>,
) -> Result<String, AppError> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(String::new());
    }
    validator(value)
}

fn date_boundary(value: &str, end_of_day: bool) -> Result<Option<NaiveDateTime>, AppError> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    let date = NaiveDate::parse_from_str(value, "%Y-%m-%d")
        .map_err(|_| AppError::InvalidInput("日期格式错误"))?;
    let time = if end_of_day {
        NaiveTime::from_hms_opt(23, 59, 59)
    } else {
        NaiveTime::from_hms_opt(0, 0, 0)
    }
    .ok_or(AppError::InvalidInput("日期格式错误"))?;
    Ok(Some(NaiveDateTime::new(date, time)))
}

fn normalized_risk_level(message: &MessageRow) -> String {
    risk_level(if message.risk_level.is_empty() {
        &message.severity
    } else {
        &message.risk_level
    })
    .unwrap_or_else(|_| "low".to_string())
}

fn normalized_security_action(value: &str) -> String {
    security_action(value).unwrap_or_else(|_| "record_only".to_string())
}

fn normalized_message_status(value: &str) -> String {
    message_status(value).unwrap_or_else(|_| "unread".to_string())
}

fn json_array(value: &str) -> Value {
    let json_text = value.trim();
    let json_text = if json_text.is_empty() {
        "[]"
    } else {
        json_text
    };
    match serde_json::from_str(json_text) {
        Ok(Value::Array(values)) => Value::Array(values),
        Ok(Value::Object(values)) => Value::Object(values),
        _ => json!([]),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn parses_message_filters_like_frontend() {
        let filters = message_filters(&json!({
            "status": "unread",
            "action": "disable_card",
            "risk_level": "critical",
            "event_type": "hook_detected",
            "card_fingerprint": "abc",
            "install_id": "install",
            "ip": "127.0.0.1",
            "start": "2026-06-01",
            "end": "2026-06-11",
            "page": 2,
            "limit": 30
        }))
        .expect("filters");

        assert_eq!("unread", filters.status);
        assert_eq!("disable_card", filters.action);
        assert_eq!("critical", filters.risk_level);
        assert_eq!("hook_detected", filters.event_type);
        assert_eq!(30, filters.limit);
        assert_eq!(30, filters.offset);
        assert_eq!(
            "2026-06-01 00:00:00",
            filters
                .start
                .expect("start")
                .format("%Y-%m-%d %H:%M:%S")
                .to_string()
        );
        assert_eq!(
            "2026-06-11 23:59:59",
            filters
                .end
                .expect("end")
                .format("%Y-%m-%d %H:%M:%S")
                .to_string()
        );
    }

    #[test]
    fn rejects_invalid_message_filters() {
        assert!(matches!(
            message_filters(&json!({"status": "new"})),
            Err(AppError::InvalidMessageStatus)
        ));
        assert!(matches!(
            message_filters(&json!({"action": "wipe_disk"})),
            Err(AppError::InvalidSecurityAction)
        ));
        assert!(matches!(
            message_filters(&json!({"event_type": "unknown"})),
            Err(AppError::InvalidSecurityEventType)
        ));
    }

    #[test]
    fn parses_detail_json_like_php_json_array() {
        assert_eq!(json!([]), json_array(""));
        assert_eq!(json!([]), json_array("not-json"));
        assert_eq!(json!([]), json_array("42"));
        assert_eq!(json!([]), json_array("\"text\""));
        assert_eq!(
            json!([{"name": "debugger_detected"}]),
            json_array(r#"[{"name":"debugger_detected"}]"#)
        );
        assert_eq!(
            json!({"ip": "127.0.0.1"}),
            json_array(r#"{"ip":"127.0.0.1"}"#)
        );
    }
}
