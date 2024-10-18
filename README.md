<div align="center">
    <h1>Aegis</h1>
    <p>Simple Web Application Firewall</p>
    <img src="https://img.shields.io/badge/status-active-green.svg">
    <img src="https://img.shields.io/badge/license-MIT-blue.svg">
    <img src="https://img.shields.io/badge/language-Rust-red.svg">
    <img src="https://img.shields.io/badge/release-3.1.0-green.svg">
    <!-- <img src="aegis.png" alt="Aegis Logo" > -->
</div>

<div align="center"> <strong>Aegis</strong> is a web application firewall written in Rust. It provides features like robust content filtering and rate limiting with redis.</div>

## Features

- **Rate Limiting with Redis**: Prevent abuse and control traffic using Redis-backed rate limiting, ensuring that your services remain performant under heavy load.
- **Custom Rules for Filtering Requests**: Define custom rules to block, allow, or monitor web traffic based on parameters such as IP, headers, URI, and more.
- **Hot Reload Configuration**: Easily update firewall rules without downtime by reloading configurations on the fly.


## Installation

1. **Prerequisites**:
    - [Rust](https://www.rust-lang.org/)
    - [Redis](https://redis.io/)
    - Optional: Docker for running Redis locally

2. **Clone the Repository**:
    ```bash
    git clone https://github.com/utibeabasi6/aegis.git
    cd aegis
    ```

3. **Run the Project**:
    Make sure Redis is running:
    ```bash
    docker run -p 6379:6379 redis
    ```

    Then, start the Aegis firewall:
    ```bash
    cargo run
    ```

## Usage

Aegis is designed to be simple and highly configurable. Once running, you can define custom rules for rate limiting, request filtering, and traffic monitoring.

### Installation

Install the latest version of Aegis by running the following command
```shell
cargo install aegis-waf
```

Start aegis by running 
```shell
aegis --config-file /path/to/your/config.yaml
```

### Example Config
```yaml
upstream: "http://localhost:8000"
default_action: "Block"
rules:
  - action: "Allow"
    condition: "All"
    type: "Regular"
    statements:
      - inspect: 
          Header:
            key: "hello"
        negate_statement: false
        match_type: "Contains"
        match_string: "world"
```

This rule only allows requests which have a header named `hello` set to `world`. For a description of the various fields, please refer to this [document](./documentation/config.md).

## Contributing

We welcome contributions! To get started:

1. **Fork the repository**:
    ```bash
    git clone https://github.com/utibeabasi6/aegis.git
    cd aegis
    ```

2. **Create a feature branch**:
    ```bash
    git checkout -b feature-branch-name
    ```

3. **Make your changes**: Add new features, fix bugs, or improve documentation.

4. **Commit your changes**:
    ```bash
    git add .
    git commit -m "Add feature or fix description"
    ```

5. **Push to your branch**:
    ```bash
    git push origin feature-branch-name
    ```

6. **Create a pull request**: Go to the repository on GitHub and submit a pull request describing your changes.

---

## License

This project is licensed under the MIT License. See the `LICENSE` file for more details.

---

## Contact

- **Author**: [Utibeabasi Umanah](https://github.com/utibeabasi6)
- **Email**: utibeabasiumanah6@gmail.com
- **Project Repository**: [Aegis on GitHub](https://github.com/utibeabasi6/aegis)