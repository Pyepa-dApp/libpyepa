use serde::{Deserialize, Serialize};

/// Represents a geographic location with latitude and longitude
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Location {
    /// Latitude coordinate
    pub latitude: f64,
    /// Longitude coordinate
    pub longitude: f64,
}

impl Location {
    /// Creates a new Location
    pub fn new(latitude: f64, longitude: f64) -> Self {
        Self {
            latitude,
            longitude,
        }
    }

    /// Calculates the distance in kilometers between two locations using the Haversine formula
    pub fn distance_to(&self, other: &Location) -> f64 {
        const EARTH_RADIUS_KM: f64 = 6371.0;

        let lat1_rad = self.latitude.to_radians();
        let lat2_rad = other.latitude.to_radians();

        let delta_lat = (other.latitude - self.latitude).to_radians();
        let delta_lon = (other.longitude - self.longitude).to_radians();

        let a = (delta_lat / 2.0).sin().powi(2)
            + lat1_rad.cos() * lat2_rad.cos() * (delta_lon / 2.0).sin().powi(2);
        let c = 2.0 * a.sqrt().atan2((1.0 - a).sqrt());

        EARTH_RADIUS_KM * c
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_distance_calculation() {
        // New York City coordinates
        let nyc = Location::new(40.7128, -74.0060);
        // Los Angeles coordinates
        let la = Location::new(34.0522, -118.2437);

        // The distance should be approximately 3935 km
        let distance = nyc.distance_to(&la);
        assert!(
            (distance - 3935.0).abs() < 50.0,
            "Distance calculation is off by more than 50 km"
        );
    }
}
