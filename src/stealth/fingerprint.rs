use rand::seq::SliceRandom;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserProfile {
    pub name: String,
    pub ja3: String,
    pub ja4: String,
    pub user_agent: String,
    pub http2_settings: Http2Settings,
    pub tcp_fingerprint: TcpFingerprint,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Http2Settings {
    pub header_table_size: u32,
    pub max_concurrent_streams: u32,
    pub initial_window_size: u32,
    pub max_frame_size: u32,
    pub max_header_list_size: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpFingerprint {
    pub window_size: u32,
    pub ttl: u8,
    pub mss: u16,
    pub window_scale: u8,
    pub timestamp: bool,
    pub sack_permitted: bool,
}

#[derive(Debug, Clone)]
pub struct TlsFingerprint {
    pub ja3: String,
    pub ja4: String,
    pub cipher_suites: Vec<u16>,
    pub extensions: Vec<u16>,
    pub curves: Vec<u16>,
}

pub struct BrowserProfiles;

impl BrowserProfiles {
    pub fn chrome_131() -> BrowserProfile {
        BrowserProfile {
            name: "Chrome 131".to_string(),
            ja3: "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0".to_string(),
            ja4: "t13d1516h2_8daaf6152771_e5627efa2ab1".to_string(),
            user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36".to_string(),
            http2_settings: Http2Settings {
                header_table_size: 65536,
                max_concurrent_streams: 1000,
                initial_window_size: 6291456,
                max_frame_size: 16384,
                max_header_list_size: 262144,
            },
            tcp_fingerprint: TcpFingerprint {
                window_size: 65535,
                ttl: 64,
                mss: 1460,
                window_scale: 8,
                timestamp: true,
                sack_permitted: true,
            },
        }
    }

    pub fn firefox_133() -> BrowserProfile {
        BrowserProfile {
            name: "Firefox 133".to_string(),
            ja3: "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-51-43-13-45-28-21,29-23-24-25-256-257,0".to_string(),
            ja4: "t13d1517h2_55b375c5d22e_06cda9e17597".to_string(),
            user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0".to_string(),
            http2_settings: Http2Settings {
                header_table_size: 65536,
                max_concurrent_streams: 100,
                initial_window_size: 131072,
                max_frame_size: 16384,
                max_header_list_size: 262144,
            },
            tcp_fingerprint: TcpFingerprint {
                window_size: 65535,
                ttl: 64,
                mss: 1460,
                window_scale: 8,
                timestamp: true,
                sack_permitted: true,
            },
        }
    }

    pub fn safari_18() -> BrowserProfile {
        BrowserProfile {
            name: "Safari 18".to_string(),
            ja3: "771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47,0-23-65281-10-11-16-5-13-18-51-45-43-27-17513-21,29-23-24-25,0".to_string(),
            ja4: "t13d1516h2_9dc949149365_3b786b063853".to_string(),
            user_agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15".to_string(),
            http2_settings: Http2Settings {
                header_table_size: 4096,
                max_concurrent_streams: 100,
                initial_window_size: 2097152,
                max_frame_size: 16384,
                max_header_list_size: 65536,
            },
            tcp_fingerprint: TcpFingerprint {
                window_size: 65535,
                ttl: 64,
                mss: 1460,
                window_scale: 6,
                timestamp: true,
                sack_permitted: true,
            },
        }
    }

    pub fn edge_120() -> BrowserProfile {
        BrowserProfile {
            name: "Edge 120".to_string(),
            ja3: "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0".to_string(),
            ja4: "t13d1516h2_8daaf6152771_e5627efa2ab1".to_string(),
            user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0".to_string(),
            http2_settings: Http2Settings {
                header_table_size: 65536,
                max_concurrent_streams: 1000,
                initial_window_size: 6291456,
                max_frame_size: 16384,
                max_header_list_size: 262144,
            },
            tcp_fingerprint: TcpFingerprint {
                window_size: 65535,
                ttl: 64,
                mss: 1460,
                window_scale: 8,
                timestamp: true,
                sack_permitted: true,
            },
        }
    }

    pub fn all_profiles() -> Vec<BrowserProfile> {
        vec![
            Self::chrome_131(),
            Self::firefox_133(),
            Self::safari_18(),
            Self::edge_120(),
        ]
    }

    pub fn random_profile() -> BrowserProfile {
        let profiles = Self::all_profiles();
        profiles.choose(&mut rand::thread_rng()).unwrap().clone()
    }

    pub fn get_profile(name: &str) -> Option<BrowserProfile> {
        match name.to_lowercase().as_str() {
            "chrome_131" | "chrome" => Some(Self::chrome_131()),
            "firefox_133" | "firefox" => Some(Self::firefox_133()),
            "safari_18" | "safari" => Some(Self::safari_18()),
            "edge_120" | "edge" => Some(Self::edge_120()),
            "random" => Some(Self::random_profile()),
            _ => None,
        }
    }
}
