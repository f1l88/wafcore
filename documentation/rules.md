# Aegis Rules Configuration Reference

Rules define how Aegis processes requests. There are two types of rules:

- **Regular Rules**:  
    - **Type**: `"Regular"`
    - **`action`**: The action to take if the rule is matched (`Allow`, `Block`, or `Count`).

    -  **`condition`**: Specifies how to evaluate multiple statements. Allowed values: `One`, `All`, or `None`

    - **`statements`**: A list of conditions to match requests. (`Header`, `QueryParameter`, `HttpMethod`, `UriPath`, QueryString`, AllHeaders`, `Cookies`, `IpSet`)
        - **`inspect`**: Specifies the part of the request to inspect (e.g., headers, query parameters). More details below

        - **`match_type`**: How to match the inspected value (`StartsWith`, `EndsWith`, `Contains`, `Exact`, `Regex`).

        - **`match_string`**: The string to match against.

- **Rate-Based Rules**:
    - **Type**: `"RateBased"`
    - **`limit`**: Maximum number of requests allowed within the evaluation window.
    - **`evaluation_window_seconds`**: The duration of the evaluation window in seconds.
    - **`key`**: The request component to use for rate-limiting (e.g., `SourceIp`).

### Field Descriptions (Statements - Inspect)

In a regular rule, you define **statements** that specify how to process a request. Below are the possible values for the `inspect` field:

1. **`Header`**: Inspect a specific HTTP header.
    - **`key`**: The name of the header to inspect.
    - Example: 
    ```yaml
    inspect:
      Header:
        key: "User-Agent"
    ```

2. **`QueryParameter`**: Inspect a specific query parameter in the request URL.
    - **`key`**: The name of the query parameter to inspect.
    - Example:
    ```yaml
    inspect:
      QueryParameter:
        key: "id"
    ```

3. **`HttpMethod`**: Inspect the HTTP method (e.g., `GET`, `POST`).
    - Example:
    ```yaml
    inspect: HttpMethod
    ```

4. **`UriPath`**: Inspect the path of the request URI (e.g., `/home`, `/login`).
    - Example:
    ```yaml
    inspect: UriPath
    ```

5. **`QueryString`**: Inspect the entire query string in the request (e.g., `?id=123&name=test`).
    - Example:
    ```yaml
    inspect: QueryString
    ```

6. **`AllHeaders`**: Inspect all request headers.
    - **`scope`**: Defines which part of the headers to inspect (all, only keys, or only values).
      - Allowed values: `All`, `Keys`, `Values`
    - **`content_filter`**: Further filters the headers to include or exclude specific headers.
      - Examples:
        - Include a header:
        ```yaml
        inspect:
          AllHeaders:
            scope: All
            content_filter:
              Include:
                key: "Authorization"
        ```
        - Exclude a header:
        ```yaml
        inspect:
          AllHeaders:
            scope: Keys
            content_filter:
              Exclude:
                key: "Cookie"
        ```

7. **`Cookies`**: Inspect all request cookies.
    - **`scope`**: Defines which part of the cookies to inspect (all, only keys, or only values).
      - Allowed values: `All`, `Keys`, `Values`
    - **`content_filter`**: Include or exclude specific cookies.
    - Example:
    ```yaml
    inspect:
      Cookies:
        scope: All
        content_filter:
          Include:
            key: "session_id"
    ```

8. **`IpSet`**: Inspect the IP address of the request.
    - **`source`**: Defines how to extract the IP address.
      - Allowed values:
        - `SourceIp`: Use the source IP of the request.
        - `Header`: Extract the IP from a specific header (e.g., `X-Forwarded-For`).
          - **`name`**: The name of the header.
          - **`position`**: Where to look for the IP address in the header (options: `First`, `Last`, `Any`).
      - Example:
      ```yaml
      inspect:
        IpSet:
          source: 
            Header:
              name: "X-Forwarded-For"
              position: Last
      ```

### Field Descriptions (Statements - Match Type)

The `match_type` field defines how the inspected value should be matched against the specified `match_string`. Below are the possible values for `match_type`:

1. **`StartsWith`**: Matches if the inspected value begins with the `match_string`.
    - Example:
    ```yaml
    match_type: "StartsWith"
    match_string: "/api"
    ```
    - Explanation: This matches any URI path that starts with `/api`, such as `/api/v1/resource`.

2. **`EndsWith`**: Matches if the inspected value ends with the `match_string`.
    - Example:
    ```yaml
    match_type: "EndsWith"
    match_string: ".html"
    ```
    - Explanation: This matches any URI path that ends with `.html`, such as `/home/index.html`.

3. **`Contains`**: Matches if the inspected value contains the `match_string`.
    - Example:
    ```yaml
    match_type: "Contains"
    match_string: "admin"
    ```
    - Explanation: This matches any part of the inspected value that contains `admin`, such as `/admin/login`.

4. **`Exact`**: Matches if the inspected value exactly equals the `match_string`.
    - Example:
    ```yaml
    match_type: "Exact"
    match_string: "POST"
    ```
    - Explanation: This matches the HTTP method if it is exactly `POST`.

5. **`Regex`**: Matches if the inspected value matches the regular expression pattern specified in `match_string`.
    - Example:
    ```yaml
    match_type: "Regex"
    match_string: "^/user/[0-9]+"
    ```
    - Explanation: This matches any URI path that starts with `/user/` followed by one or more digits, such as `/user/123`.

## Configuration Examples

### Block requests from the curl user agent
```yaml
rules:
  - type: "Regular"
    action: "Block"
    condition: "All"
    statements:
      - inspect: 
          Header:
            key: "User-Agent"
        match_type: "Contains"
        match_string: "curl"

```

## Block requests if content type header is `application/json`

```yaml
rules:
  - type: "Regular"
    action: "Block"
    condition: "All"
    statements:
      - inspect:
          Header:
            key: "Content-Type"   # Inspect the Content-Type header
        match_type: "Exact"        # Match if the value is exactly "application/json"
        match_string: "application/json"
```

### Allow requests if `id` query parameter starts with `123`
```yaml
rules:
  - type: "Regular"
    action: "Allow"
    condition: "One"
    statements:
      - inspect:
          QueryParameter:
            key: "id"              # Inspect the "id" query parameter
        match_type: "StartsWith"    # Match if the value starts with "123"
        match_string: "123"
```

### Block requests if HTTP Methos is `POST`
```yaml
rules:
  - type: "Regular"
    action: "Block"
    condition: "All"
    statements:
      - inspect: HttpMethod         # Inspect the HTTP method (GET, POST, etc.)
        match_type: "Exact"
        match_string: "POST"        # Block if the request is a POST method
```

### Block requests from localhost
```yaml
rules:
  - type: "Regular"
    action: "Block"
    condition: "All"
    statements:
      - inspect:
          AllHeaders:
            scope: Values              # Inspect all headers
            content_filter: 
                Include:  # Apply a content filter (e.g., inspect specific headers)
                    key: "X-Forwarded-For" # Include only the "X-Forwarded-For" header for inspection
        match_type: "Contains"
        match_string: "127.0.0.1"
```

### Block request if all cookies are equal to `invalid`
```yaml
rules:
  - type: "Regular"
    action: "Block"
    condition: "All"
    statements:
      - inspect:
          Cookies:
            scope: All              # Inspect all cookies
            content_filter: 
                Exclude: # Exclude specific cookie keys from the match
                    key: "session_id"
        match_type: "Exact"
        match_string: "invalid"
```

### Block request if the first ip in the `X-Forwarded-For` header is `192.168.1.1`
```yaml
rules:
  - type: "Regular"
    action: "Block"
    condition: "All"
    statements:
      - inspect:
          IpSet:
            source: 
                Header:          # Inspect IP address from a header
                    name: "X-Forwarded-For" # Specify the header name
                    position: First         # Use the first IP in the header
        match_type: "Exact"
        match_string: "192.168.1.1" # Block if the IP matches "192.168.1.1"
```

### Limit requests to 1000 rpm

```yaml
rules:
  - type: "RateBased"
    limit: 1000
    evaluation_window_seconds: 60
    key: "SourceIp"
```