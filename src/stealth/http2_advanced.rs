use crate::stealth::BrowserProfile;

/// HTTP/2 SETTINGS frame identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SettingId {
    HeaderTableSize = 1,
    EnablePush = 2,
    MaxConcurrentStreams = 3,
    InitialWindowSize = 4,
    MaxFrameSize = 5,
    MaxHeaderListSize = 6,
    EnableConnectProtocol = 8,
    NoRfc7540Priorities = 9,
}

#[derive(Debug, Clone)]
pub struct Setting {
    pub id: SettingId,
    pub value: u32,
}

/// HTTP/2 Advanced Fingerprinter
/// Emula SETTINGS frame order e timing específicos de cada browser
pub struct Http2Fingerprinter {
    browser_profile: BrowserProfile,
}

impl Http2Fingerprinter {
    pub fn new(browser_profile: BrowserProfile) -> Self {
        Self { browser_profile }
    }

    /// Retorna ordem correta de SETTINGS por browser (CRITICAL!)
    /// Cada browser envia SETTINGS em ordem específica - detectável por WAFs
    pub fn build_settings_frame(&self) -> Vec<Setting> {
        match self.browser_profile.name.as_str() {
            "Chrome 131" | "chrome_131" => self.chrome_settings(),
            "Firefox 133" | "firefox_133" => self.firefox_settings(),
            "Safari 18" | "safari_18" => self.safari_settings(),
            "Edge 120" | "edge_120" => self.edge_settings(),
            _ => self.chrome_settings(), // Default to Chrome
        }
    }

    /// Chrome 131 SETTINGS order: 1,2,3,4,5,6
    fn chrome_settings(&self) -> Vec<Setting> {
        vec![
            Setting {
                id: SettingId::HeaderTableSize,
                value: 65536,
            },
            Setting {
                id: SettingId::EnablePush,
                value: 0,
            },
            Setting {
                id: SettingId::MaxConcurrentStreams,
                value: 1000,
            },
            Setting {
                id: SettingId::InitialWindowSize,
                value: 6291456,
            },
            Setting {
                id: SettingId::MaxFrameSize,
                value: 16384,
            },
            Setting {
                id: SettingId::MaxHeaderListSize,
                value: 262144,
            },
        ]
    }

    /// Firefox 133 SETTINGS order: 1,4,5,3,2 (DIFERENTE do Chrome!)
    fn firefox_settings(&self) -> Vec<Setting> {
        vec![
            Setting {
                id: SettingId::HeaderTableSize,
                value: 65536,
            },
            Setting {
                id: SettingId::InitialWindowSize,
                value: 131072,
            },
            Setting {
                id: SettingId::MaxFrameSize,
                value: 16384,
            },
            Setting {
                id: SettingId::MaxConcurrentStreams,
                value: 100,
            },
            Setting {
                id: SettingId::EnablePush,
                value: 0,
            },
        ]
    }

    /// Safari 18 SETTINGS order: 2,3,4,5,6,1 (TOTALMENTE DIFERENTE!)
    fn safari_settings(&self) -> Vec<Setting> {
        vec![
            Setting {
                id: SettingId::EnablePush,
                value: 0,
            },
            Setting {
                id: SettingId::MaxConcurrentStreams,
                value: 100,
            },
            Setting {
                id: SettingId::InitialWindowSize,
                value: 2097152,
            },
            Setting {
                id: SettingId::MaxFrameSize,
                value: 16384,
            },
            Setting {
                id: SettingId::MaxHeaderListSize,
                value: 65536,
            },
            Setting {
                id: SettingId::HeaderTableSize,
                value: 4096,
            },
        ]
    }

    /// Edge 120 SETTINGS order: Same as Chrome (Chromium-based)
    fn edge_settings(&self) -> Vec<Setting> {
        self.chrome_settings()
    }

    /// WINDOW_UPDATE timing strategy (browser-specific)
    pub fn window_update_strategy(&self) -> WindowUpdateStrategy {
        match self.browser_profile.name.as_str() {
            "Chrome 131" | "chrome_131" => WindowUpdateStrategy {
                initial_window: 6291456,
                update_threshold: 0.5,
                jitter_ms: 10,
            },
            "Firefox 133" | "firefox_133" => WindowUpdateStrategy {
                initial_window: 131072,
                update_threshold: 0.75,
                jitter_ms: 5,
            },
            _ => WindowUpdateStrategy::default(),
        }
    }

    /// HTTP/2 Priority Frames (Chrome usa, Firefox não)
    pub fn should_use_priority(&self) -> bool {
        self.browser_profile.name.contains("Chrome") || self.browser_profile.name.contains("Edge")
    }

    /// Stream dependency tree (Chrome-specific)
    pub fn build_priority_tree(&self) -> Option<Vec<StreamDependency>> {
        if self.should_use_priority() {
            Some(vec![
                StreamDependency {
                    stream_id: 0,
                    weight: 201,
                    exclusive: false,
                },
                StreamDependency {
                    stream_id: 0,
                    weight: 101,
                    exclusive: false,
                },
            ])
        } else {
            None
        }
    }
}

#[derive(Debug, Clone)]
pub struct WindowUpdateStrategy {
    pub initial_window: u32,
    pub update_threshold: f32,
    pub jitter_ms: u64,
}

impl Default for WindowUpdateStrategy {
    fn default() -> Self {
        Self {
            initial_window: 6291456,
            update_threshold: 0.5,
            jitter_ms: 10,
        }
    }
}

#[derive(Debug, Clone)]
pub struct StreamDependency {
    pub stream_id: u32,
    pub weight: u8,
    pub exclusive: bool,
}

/// Gera Akamai HTTP/2 Fingerprint (2025 detection method)
/// Format: settings_order|window_size|priority_used
pub fn generate_akamai_h2_fingerprint(settings: &[Setting], window: u32, has_priority: bool) -> String {
    let settings_order: Vec<String> = settings
        .iter()
        .map(|s| format!("{}", s.id as u32))
        .collect();
    
    format!(
        "{}|{}|{}",
        settings_order.join(":"),
        window,
        if has_priority { "1" } else { "0" }
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stealth::BrowserProfiles;

    #[test]
    fn test_chrome_settings_order() {
        let profile = BrowserProfiles::chrome_131();
        let fp = Http2Fingerprinter::new(profile);
        let settings = fp.build_settings_frame();

        // Chrome order: 1,2,3,4,5,6
        assert_eq!(settings[0].id, SettingId::HeaderTableSize);
        assert_eq!(settings[1].id, SettingId::EnablePush);
        assert_eq!(settings[2].id, SettingId::MaxConcurrentStreams);
        assert_eq!(settings[3].id, SettingId::InitialWindowSize);
        assert_eq!(settings[4].id, SettingId::MaxFrameSize);
        assert_eq!(settings[5].id, SettingId::MaxHeaderListSize);
    }

    #[test]
    fn test_firefox_different_order() {
        let profile = BrowserProfiles::firefox_133();
        let fp = Http2Fingerprinter::new(profile);
        let settings = fp.build_settings_frame();

        // Firefox order: 1,4,5,3,2 (DIFERENTE!)
        assert_eq!(settings[0].id, SettingId::HeaderTableSize);
        assert_eq!(settings[1].id, SettingId::InitialWindowSize);
        assert_eq!(settings[2].id, SettingId::MaxFrameSize);
    }

    #[test]
    fn test_akamai_fingerprint() {
        let settings = vec![
            Setting { id: SettingId::HeaderTableSize, value: 65536 },
            Setting { id: SettingId::EnablePush, value: 0 },
        ];
        
        let fp = generate_akamai_h2_fingerprint(&settings, 6291456, true);
        assert_eq!(fp, "1:2|6291456|1");
    }
}
