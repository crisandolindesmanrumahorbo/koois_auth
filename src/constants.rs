pub const OK_RESPONSE: &str = "HTTP/1.1 200 OK\r\n\
            Access-Control-Allow-Origin: *\r\n\
            Access-Control-Allow-Methods: POST, GET, OPTIONS\r\n\
            Access-Control-Allow-Headers: Content-Type\r\n\
            Access-Control-Max-Age: 86400\r\n\
            Content-Type: application/json\r\n\
            \r\n";
pub const NO_CONTENT: &str = "HTTP/1.1 204 No Content\r\n\r\n";
pub const BAD_REQUEST: &str = "HTTP/1.1 400 Bad Request\r\n\r\n";
pub const UNAUTHORIZED: &str = "HTTP/1.1 401 Unauthorized\r\n\r\n";
pub const NOT_FOUND: &str = "HTTP/1.1 404 Not Found\r\n\r\n";
pub const INTERNAL_ERROR: &str = "HTTP/1.1 500 Internal Error\r\n\r\n";
