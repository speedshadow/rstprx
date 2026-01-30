use crate::error::{Error, Result};
use bytes::Bytes;
use http::{Request, Uri};
use http_body_util::Full;
use url::Url;

pub struct RequestDirector {
    target_url: Url,
}

impl RequestDirector {
    pub fn new(target_url: &str) -> Result<Self> {
        let target_url = Url::parse(target_url)
            .map_err(|e| Error::Proxy(format!("Invalid target URL: {}", e)))?;
        
        Ok(Self { target_url })
    }

    pub fn modify_request(
        &self,
        mut parts: http::request::Parts,
        body: Full<Bytes>,
    ) -> Result<Request<Full<Bytes>>> {
        let path_and_query = parts
            .uri
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/");

        let new_uri = format!(
            "{}://{}{}",
            self.target_url.scheme(),
            self.target_url.host_str().unwrap_or(""),
            path_and_query
        );

        parts.uri = new_uri
            .parse::<Uri>()
            .map_err(|e| Error::Proxy(format!("Failed to parse URI: {}", e)))?;

        let host_value = self.target_url.host_str().unwrap_or("");
        parts.headers.insert(
            http::header::HOST,
            host_value.parse().map_err(|e| Error::Proxy(format!("Invalid host: {}", e)))?,
        );

        Ok(Request::from_parts(parts, body))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::Method;

    #[test]
    fn test_request_director() {
        let director = RequestDirector::new("https://example.com").unwrap();
        
        let req = Request::builder()
            .method(Method::GET)
            .uri("/test/path")
            .body(Full::new(Bytes::new()))
            .unwrap();

        let (parts, body) = req.into_parts();
        let modified = director.modify_request(parts, body).unwrap();

        assert_eq!(modified.uri().scheme_str(), Some("https"));
        assert_eq!(modified.uri().host(), Some("example.com"));
        assert_eq!(modified.uri().path(), "/test/path");
    }
}
