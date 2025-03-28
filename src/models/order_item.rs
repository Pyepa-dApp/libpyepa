use serde::{Deserialize, Serialize};

/// Represents an item in an order
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct OrderItem {
    /// Unique identifier for the item
    pub item_id: String,
    /// Quantity of the item ordered
    pub quantity: u32,
}

impl OrderItem {
    /// Creates a new OrderItem
    pub fn new(item_id: String, quantity: u32) -> Self {
        Self { item_id, quantity }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_order_item_creation() {
        let order_item = OrderItem::new("item-123".to_string(), 5);

        assert_eq!(order_item.item_id, "item-123");
        assert_eq!(order_item.quantity, 5);
    }
}
