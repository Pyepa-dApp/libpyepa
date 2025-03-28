use serde::{Deserialize, Serialize};

/// Represents an item that can be ordered from a vendor
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Item {
    /// Unique identifier for the item
    pub item_id: String,
    /// Name of the item
    pub item_name: String,
    /// Optional description of the item
    pub description: Option<String>,
    /// Optional price of the item (as a string to support various currencies and formats)
    pub price: Option<String>,
    /// Optional availability information
    pub availability: Option<String>,
    /// Tags for categorizing and searching for the item
    pub tags: Vec<String>,
}

impl Item {
    /// Creates a new Item with required fields
    pub fn new(item_id: String, item_name: String) -> Self {
        Self {
            item_id,
            item_name,
            description: None,
            price: None,
            availability: None,
            tags: Vec::new(),
        }
    }

    /// Sets the description of the item
    pub fn with_description(mut self, description: String) -> Self {
        self.description = Some(description);
        self
    }

    /// Sets the price of the item
    pub fn with_price(mut self, price: String) -> Self {
        self.price = Some(price);
        self
    }

    /// Sets the availability of the item
    pub fn with_availability(mut self, availability: String) -> Self {
        self.availability = Some(availability);
        self
    }

    /// Adds tags to the item
    pub fn with_tags(mut self, tags: Vec<String>) -> Self {
        self.tags = tags;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_item_builder() {
        let item = Item::new("item-123".to_string(), "Test Item".to_string())
            .with_description("A test item".to_string())
            .with_price("10.99".to_string())
            .with_availability("In Stock".to_string())
            .with_tags(vec!["test".to_string(), "example".to_string()]);

        assert_eq!(item.item_id, "item-123");
        assert_eq!(item.item_name, "Test Item");
        assert_eq!(item.description, Some("A test item".to_string()));
        assert_eq!(item.price, Some("10.99".to_string()));
        assert_eq!(item.availability, Some("In Stock".to_string()));
        assert_eq!(item.tags, vec!["test".to_string(), "example".to_string()]);
    }
}
