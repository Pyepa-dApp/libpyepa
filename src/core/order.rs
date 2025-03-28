//! Order data structures and state machine

use crate::core::error::Error;
use crate::core::types::OrderState;
use crate::models::{Message, Order};
use crate::Result;

/// Order manager for handling order state transitions
pub struct OrderManager;

impl OrderManager {
    /// Creates a new OrderManager
    pub fn new() -> Self {
        Self
    }

    /// Processes a message and updates the order state accordingly
    pub fn process_message(&self, order: &mut Order, message: &Message) -> Result<()> {
        // Parse the current state
        let current_state = OrderState::from_str(&order.current_state).ok_or_else(|| {
            Error::InvalidState(format!("Invalid order state: {}", order.current_state))
        })?;

        // Parse the message status if available
        let status = match &message.status {
            Some(s) => s.as_str(),
            None => return Err(Error::InvalidData("Message status is required".into())),
        };

        // Determine the new state based on the message type and current state
        let new_state = match message.message_type.as_str() {
            "order_acceptance" if current_state == OrderState::Created => match status {
                "accepted" => OrderState::Accepted,
                "rejected" => OrderState::Rejected,
                _ => {
                    return Err(Error::InvalidData(format!(
                        "Invalid status for order_acceptance: {}",
                        status
                    )))
                }
            },
            "dispatch_notification" if current_state == OrderState::Accepted => match status {
                "dispatched" => OrderState::Dispatched,
                _ => {
                    return Err(Error::InvalidData(format!(
                        "Invalid status for dispatch_notification: {}",
                        status
                    )))
                }
            },
            "delivery_notification" if current_state == OrderState::Dispatched => match status {
                "delivered" => OrderState::Delivered,
                _ => {
                    return Err(Error::InvalidData(format!(
                        "Invalid status for delivery_notification: {}",
                        status
                    )))
                }
            },
            "delivery_response" if current_state == OrderState::Delivered => match status {
                "delivery_accepted" => OrderState::DeliveryAccepted,
                "delivery_rejected" => OrderState::DeliveryRejected,
                _ => {
                    return Err(Error::InvalidData(format!(
                        "Invalid status for delivery_response: {}",
                        status
                    )))
                }
            },
            "return_request"
                if current_state == OrderState::DeliveryAccepted
                    || current_state == OrderState::DeliveryRejected =>
            {
                match status {
                    "return_requested" => OrderState::ReturnRequested,
                    _ => {
                        return Err(Error::InvalidData(format!(
                            "Invalid status for return_request: {}",
                            status
                        )))
                    }
                }
            }
            "return_response" if current_state == OrderState::ReturnRequested => match status {
                "return_accepted" => OrderState::ReturnAccepted,
                "return_rejected" => OrderState::ReturnRejected,
                _ => {
                    return Err(Error::InvalidData(format!(
                        "Invalid status for return_response: {}",
                        status
                    )))
                }
            },
            "dispute_initiation" => OrderState::Disputed,
            _ => {
                return Err(Error::InvalidState(format!(
                    "Invalid state transition: from {} with message type {} and status {}",
                    current_state.as_str(),
                    message.message_type,
                    status
                )))
            }
        };

        // Update the order state
        order.current_state = new_state.as_str().to_string();

        Ok(())
    }

    /// Checks if a state transition is valid
    pub fn is_valid_transition(&self, from: &OrderState, to: &OrderState) -> bool {
        match (from, to) {
            (OrderState::Created, OrderState::Accepted) => true,
            (OrderState::Created, OrderState::Rejected) => true,
            (OrderState::Accepted, OrderState::Dispatched) => true,
            (OrderState::Dispatched, OrderState::Delivered) => true,
            (OrderState::Delivered, OrderState::DeliveryAccepted) => true,
            (OrderState::Delivered, OrderState::DeliveryRejected) => true,
            (OrderState::DeliveryAccepted, OrderState::Completed) => true,
            (OrderState::DeliveryAccepted, OrderState::ReturnRequested) => true,
            (OrderState::DeliveryRejected, OrderState::ReturnRequested) => true,
            (OrderState::ReturnRequested, OrderState::ReturnAccepted) => true,
            (OrderState::ReturnRequested, OrderState::ReturnRejected) => true,
            (OrderState::ReturnAccepted, OrderState::Completed) => true,
            (_, OrderState::Disputed) => true, // Can enter dispute from any state
            (_, OrderState::Cancelled) => *from != OrderState::Completed, // Can cancel from any state except completed
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Message, OrderItem};

    fn create_test_order() -> Order {
        Order {
            order_id: "order-123".to_string(),
            buyer_public_key: "buyer_key_123".to_string(),
            vendor_public_key: "vendor_key_456".to_string(),
            order_items: vec![OrderItem::new("item-123".to_string(), 2)],
            total_amount: "20.99".to_string(),
            buyer_location: None,
            created_timestamp: 1632150000,
            current_state: OrderState::Created.as_str().to_string(),
            payment_method: "BTC".to_string(),
            payment_details: "payment_details_123".to_string(),
            signature: "signature_123".to_string(),
        }
    }

    fn create_message(message_type: &str, status: &str) -> Message {
        Message {
            message_type: message_type.to_string(),
            order_id: "order-123".to_string(),
            status: Some(status.to_string()),
            timestamp: 1632150000,
            payload: None,
            signature: "signature_123".to_string(),
        }
    }

    #[test]
    fn test_valid_order_flow() {
        let order_manager = OrderManager::new();
        let mut order = create_test_order();

        // Test acceptance
        let acceptance_message = create_message("order_acceptance", "accepted");
        order_manager
            .process_message(&mut order, &acceptance_message)
            .unwrap();
        assert_eq!(order.current_state, OrderState::Accepted.as_str());

        // Test dispatch
        let dispatch_message = create_message("dispatch_notification", "dispatched");
        order_manager
            .process_message(&mut order, &dispatch_message)
            .unwrap();
        assert_eq!(order.current_state, OrderState::Dispatched.as_str());

        // Test delivery
        let delivery_message = create_message("delivery_notification", "delivered");
        order_manager
            .process_message(&mut order, &delivery_message)
            .unwrap();
        assert_eq!(order.current_state, OrderState::Delivered.as_str());

        // Test delivery acceptance
        let delivery_response_message = create_message("delivery_response", "delivery_accepted");
        order_manager
            .process_message(&mut order, &delivery_response_message)
            .unwrap();
        assert_eq!(order.current_state, OrderState::DeliveryAccepted.as_str());
    }

    #[test]
    fn test_invalid_transition() {
        let order_manager = OrderManager::new();
        let mut order = create_test_order();

        // Try to dispatch before acceptance
        let dispatch_message = create_message("dispatch_notification", "dispatched");
        let result = order_manager.process_message(&mut order, &dispatch_message);
        assert!(result.is_err());

        // Ensure the state hasn't changed
        assert_eq!(order.current_state, OrderState::Created.as_str());
    }
}
