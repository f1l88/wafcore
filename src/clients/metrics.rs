use opentelemetry::{
    global,
    metrics::{Counter, Histogram},
};

#[derive(Clone, Debug)]
pub struct AegisMetrics {
    pub blocked_requests_counter: Counter<u64>,
    pub total_requests_counter: Counter<u64>,
    pub allowed_requests_counter: Counter<u64>,
    pub rate_limited_requests_counter: Counter<u64>,
    pub request_duration_histogram: Histogram<f64>,
}

impl AegisMetrics {
    pub fn new() -> Self {
        // Create a meter from the global MeterProvider.
        let meter = global::meter("aegis");

        // Create a Counter Instrument.
        let blocked_requests_counter = meter.u64_counter("blocked_requests_counter").init();
        let total_requests_counter = meter.u64_counter("total_requests_counter").init();
        let allowed_requests_counter = meter.u64_counter("allowed_requests_counter").init();
        let rate_limited_requests_counter =
            meter.u64_counter("rate_limited_requests_counter").init();
        let request_duration_histogram = meter.f64_histogram("request_duration_histogram").init();

        AegisMetrics {
            blocked_requests_counter,
            total_requests_counter,
            allowed_requests_counter,
            rate_limited_requests_counter,
            request_duration_histogram,
        }
    }
}
