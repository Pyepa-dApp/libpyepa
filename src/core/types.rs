//! Common data types and enums

/// Order state enum
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OrderState {
    /// Order has been created but not yet accepted or rejected
    Created,
    /// Order has been accepted by the vendor
    Accepted,
    /// Order has been rejected by the vendor
    Rejected,
    /// Order has been dispatched by the vendor
    Dispatched,
    /// Order has been delivered
    Delivered,
    /// Delivery has been accepted by the buyer
    DeliveryAccepted,
    /// Delivery has been rejected by the buyer
    DeliveryRejected,
    /// Return has been requested by the buyer
    ReturnRequested,
    /// Return has been accepted by the vendor
    ReturnAccepted,
    /// Return has been rejected by the vendor
    ReturnRejected,
    /// Order has been completed
    Completed,
    /// Order is in dispute
    Disputed,
    /// Order has been cancelled
    Cancelled,
}

impl OrderState {
    /// Converts the enum to a string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            OrderState::Created => "created",
            OrderState::Accepted => "accepted",
            OrderState::Rejected => "rejected",
            OrderState::Dispatched => "dispatched",
            OrderState::Delivered => "delivered",
            OrderState::DeliveryAccepted => "delivery_accepted",
            OrderState::DeliveryRejected => "delivery_rejected",
            OrderState::ReturnRequested => "return_requested",
            OrderState::ReturnAccepted => "return_accepted",
            OrderState::ReturnRejected => "return_rejected",
            OrderState::Completed => "completed",
            OrderState::Disputed => "disputed",
            OrderState::Cancelled => "cancelled",
        }
    }

    /// Converts a string to an OrderState enum
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "created" => Some(OrderState::Created),
            "accepted" => Some(OrderState::Accepted),
            "rejected" => Some(OrderState::Rejected),
            "dispatched" => Some(OrderState::Dispatched),
            "delivered" => Some(OrderState::Delivered),
            "delivery_accepted" => Some(OrderState::DeliveryAccepted),
            "delivery_rejected" => Some(OrderState::DeliveryRejected),
            "return_requested" => Some(OrderState::ReturnRequested),
            "return_accepted" => Some(OrderState::ReturnAccepted),
            "return_rejected" => Some(OrderState::ReturnRejected),
            "completed" => Some(OrderState::Completed),
            "disputed" => Some(OrderState::Disputed),
            "cancelled" => Some(OrderState::Cancelled),
            _ => None,
        }
    }
}

/// Message type enum
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessageType {
    /// Order acceptance message
    OrderAcceptance,
    /// Order rejection message
    OrderRejection,
    /// Dispatch notification message
    DispatchNotification,
    /// Delivery notification message
    DeliveryNotification,
    /// Delivery response message
    DeliveryResponse,
    /// Return request message
    ReturnRequest,
    /// Return response message
    ReturnResponse,
    /// Dispute initiation message
    DisputeInitiation,
    /// Dispute evidence message
    DisputeEvidence,
    /// Dispute resolution message
    DisputeResolution,
    /// General message
    General,
}

impl MessageType {
    /// Converts the enum to a string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            MessageType::OrderAcceptance => "order_acceptance",
            MessageType::OrderRejection => "order_rejection",
            MessageType::DispatchNotification => "dispatch_notification",
            MessageType::DeliveryNotification => "delivery_notification",
            MessageType::DeliveryResponse => "delivery_response",
            MessageType::ReturnRequest => "return_request",
            MessageType::ReturnResponse => "return_response",
            MessageType::DisputeInitiation => "dispute_initiation",
            MessageType::DisputeEvidence => "dispute_evidence",
            MessageType::DisputeResolution => "dispute_resolution",
            MessageType::General => "general",
        }
    }

    /// Converts a string to a MessageType enum
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "order_acceptance" => Some(MessageType::OrderAcceptance),
            "order_rejection" => Some(MessageType::OrderRejection),
            "dispatch_notification" => Some(MessageType::DispatchNotification),
            "delivery_notification" => Some(MessageType::DeliveryNotification),
            "delivery_response" => Some(MessageType::DeliveryResponse),
            "return_request" => Some(MessageType::ReturnRequest),
            "return_response" => Some(MessageType::ReturnResponse),
            "dispute_initiation" => Some(MessageType::DisputeInitiation),
            "dispute_evidence" => Some(MessageType::DisputeEvidence),
            "dispute_resolution" => Some(MessageType::DisputeResolution),
            "general" => Some(MessageType::General),
            _ => None,
        }
    }
}
