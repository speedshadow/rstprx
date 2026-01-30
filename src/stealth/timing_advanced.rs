use rand::Rng;
use rand_distr::{Distribution, LogNormal, Normal};
use std::time::{Duration, Instant};
use tokio::time::sleep;

/// Human Timing Simulator
/// Usa distribuições estatísticas realistas para simular comportamento humano
/// Resiste a ML-based bot detection
pub struct HumanTimingSimulator {
    think_time_dist: LogNormal<f64>,
    typing_speed_wpm: u32,
    request_history: Vec<Instant>,
}

impl HumanTimingSimulator {
    pub fn new() -> Self {
        // Log-normal distribution (padrão humano documentado em HCI research)
        // μ=6.0, σ=1.5 resulta em delays realistas 100ms-30s
        let think_time_dist = LogNormal::new(6.0, 1.5)
            .expect("Failed to create log-normal distribution");

        Self {
            think_time_dist,
            typing_speed_wpm: 40, // Velocidade média humana
            request_history: Vec::new(),
        }
    }

    /// Calcula delay baseado em distribuição log-normal (comportamento humano real)
    pub fn calculate_human_delay(&self) -> Duration {
        let mut rng = rand::thread_rng();
        let delay_ms = self.think_time_dist.sample(&mut rng);

        // Clamp entre valores realistas: 100ms (muito rápido) até 30s (pensando)
        let clamped = delay_ms.max(100.0).min(30_000.0);
        Duration::from_millis(clamped as u64)
    }

    /// Aplica delay com jitter gaussiano
    pub async fn apply_human_delay(&mut self) {
        let base_delay = self.calculate_human_delay();
        
        // Adicionar jitter gaussiano (±15%)
        let jitter = {
            let mut rng = rand::thread_rng();
            let normal = Normal::new(0.0, 0.15).unwrap();
            normal.sample(&mut rng)
        };

        let jittered = (base_delay.as_millis() as f64 * (1.0 + jitter))
            .max(50.0) as u64;

        self.request_history.push(Instant::now());
        sleep(Duration::from_millis(jittered)).await;
    }

    /// Simula velocidade de digitação (para forms, searches, etc)
    pub fn calculate_typing_delay(&self, text_length: usize) -> Duration {
        // WPM to milliseconds per character
        // Average word = 5 characters, so chars_per_min = WPM * 5
        let chars_per_min = self.typing_speed_wpm as f64 * 5.0;
        let ms_per_char = 60_000.0 / chars_per_min;

        let mut total_ms = 0.0;
        let mut rng = rand::thread_rng();

        for _ in 0..text_length {
            // Variação aleatória ±30% (humanos variam velocidade)
            let normal = Normal::new(1.0, 0.3).unwrap();
            let jitter: f64 = normal.sample(&mut rng);
            total_ms += ms_per_char * jitter.abs();
        }

        Duration::from_millis(total_ms as u64)
    }

    /// Detecta e mitiga burst patterns (comportamento bot)
    pub async fn check_and_mitigate_burst(&mut self) -> bool {
        // Limpar histórico antigo (> 1 minuto)
        let now = Instant::now();
        self.request_history.retain(|&instant| {
            now.duration_since(instant) < Duration::from_secs(60)
        });

        if self.request_history.len() < 5 {
            return false; // Não há burst
        }

        // Analisar últimos 5 requests
        let recent = &self.request_history[self.request_history.len() - 5..];
        let time_span = recent.last().unwrap().duration_since(*recent.first().unwrap());

        // Se 5 requests em < 2 segundos = BURST (bot behavior!)
        if time_span < Duration::from_secs(2) {
            // Aplicar backoff exponencial
            let backoff_secs = rand::thread_rng().gen_range(2..5);
            tracing::warn!("Burst detected! Applying backoff: {}s", backoff_secs);
            
            sleep(Duration::from_secs(backoff_secs)).await;
            true
        } else {
            false
        }
    }

    /// Calcula "think time" baseado no tipo de conteúdo
    pub fn content_based_delay(&self, content_type: ContentType) -> Duration {
        let base_ms = match content_type {
            ContentType::HtmlPage => 3000,      // Ler página: ~3s
            ContentType::Image => 500,           // Ver imagem: ~0.5s
            ContentType::ApiJson => 200,         // API response: ~0.2s
            ContentType::Video => 10000,         // Assistir vídeo: ~10s
            ContentType::Download => 1000,       // Download: ~1s
        };

        // Adicionar variação log-normal
        let mut rng = rand::thread_rng();
        let variation = LogNormal::new(0.0, 0.5).unwrap();
        let multiplier: f64 = variation.sample(&mut rng);

        Duration::from_millis((base_ms as f64 * multiplier.abs()) as u64)
    }
}

impl Default for HumanTimingSimulator {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy)]
pub enum ContentType {
    HtmlPage,
    Image,
    ApiJson,
    Video,
    Download,
}

/// Connection Strategy per browser
/// Browsers têm padrões únicos de keep-alive e connection reuse
pub struct ConnectionStrategy {
    max_requests_per_connection: u32,
    idle_timeout: Duration,
    #[allow(dead_code)]
    browser_type: String,
}

impl ConnectionStrategy {
    pub fn for_browser(browser: &str) -> Self {
        match browser {
            "Chrome 131" | "chrome_131" | "Edge 120" | "edge_120" => Self {
                max_requests_per_connection: 100,
                idle_timeout: Duration::from_secs(300), // 5 min
                browser_type: browser.to_string(),
            },
            "Firefox 133" | "firefox_133" => Self {
                max_requests_per_connection: 60,
                idle_timeout: Duration::from_secs(115), // 115s
                browser_type: browser.to_string(),
            },
            "Safari 18" | "safari_18" => Self {
                max_requests_per_connection: 50,
                idle_timeout: Duration::from_secs(90), // 90s
                browser_type: browser.to_string(),
            },
            _ => Self::default(),
        }
    }

    /// Determina se deve fechar conexão (baseado em uso e tempo)
    pub fn should_close_connection(&self, request_count: u32, last_used: Instant) -> bool {
        request_count >= self.max_requests_per_connection
            || last_used.elapsed() > self.idle_timeout
    }

    /// Calcula timeout para próximo request na mesma conexão
    pub fn connection_reuse_delay(&self) -> Duration {
        use rand::Rng;
        // Pequeno delay entre requests na mesma conexão (10-50ms)
        let ms = rand::thread_rng().gen_range(10..50);
        Duration::from_millis(ms)
    }
}

impl Default for ConnectionStrategy {
    fn default() -> Self {
        Self {
            max_requests_per_connection: 100,
            idle_timeout: Duration::from_secs(300),
            browser_type: "Chrome 131".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_human_delay_distribution() {
        let sim = HumanTimingSimulator::new();
        
        // Gerar 100 samples e verificar distribuição
        let delays: Vec<_> = (0..100)
            .map(|_| sim.calculate_human_delay().as_millis())
            .collect();

        // Verificar que delays estão no range esperado
        assert!(delays.iter().all(|&d| d >= 100 && d <= 30_000));

        // Média deve estar em torno de exp(μ) ≈ exp(6) ≈ 403ms
        let mean: u128 = delays.iter().sum::<u128>() / delays.len() as u128;
        assert!(mean > 200 && mean < 2000); // Média realista
    }

    #[test]
    fn test_typing_speed() {
        let sim = HumanTimingSimulator::new();
        
        let delay = sim.calculate_typing_delay(10);
        
        // 10 caracteres a 40 WPM ≈ 3 segundos
        let ms = delay.as_millis();
        assert!(ms > 1000 && ms < 5000);
    }

    #[tokio::test]
    async fn test_burst_detection() {
        let mut sim = HumanTimingSimulator::new();
        
        // Simular burst (5 requests rápidos)
        for _ in 0..5 {
            sim.request_history.push(Instant::now());
        }
        
        let detected = sim.check_and_mitigate_burst().await;
        assert!(detected);
    }

    #[test]
    fn test_content_based_delays() {
        let sim = HumanTimingSimulator::new();
        
        let html_delay = sim.content_based_delay(ContentType::HtmlPage);
        let api_delay = sim.content_based_delay(ContentType::ApiJson);
        
        // HTML page deve ter delay maior que API
        assert!(html_delay > api_delay);
    }

    #[test]
    fn test_connection_strategy_chrome() {
        let strategy = ConnectionStrategy::for_browser("Chrome 131");
        
        assert_eq!(strategy.max_requests_per_connection, 100);
        assert_eq!(strategy.idle_timeout, Duration::from_secs(300));
    }

    #[test]
    fn test_connection_strategy_firefox() {
        let strategy = ConnectionStrategy::for_browser("Firefox 133");
        
        assert_eq!(strategy.max_requests_per_connection, 60);
        assert_eq!(strategy.idle_timeout, Duration::from_secs(115));
    }

    #[test]
    fn test_should_close_connection() {
        let strategy = ConnectionStrategy::for_browser("Chrome 131");
        
        // 100 requests = deve fechar
        assert!(strategy.should_close_connection(100, Instant::now()));
        
        // Timeout excedido = deve fechar
        let old_instant = Instant::now() - Duration::from_secs(400);
        assert!(strategy.should_close_connection(50, old_instant));
        
        // Normal = não deve fechar
        assert!(!strategy.should_close_connection(50, Instant::now()));
    }
}
