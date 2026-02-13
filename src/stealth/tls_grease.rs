use rand::seq::SliceRandom;
use rand::Rng;

/// GREASE (Generate Random Extensions And Sustain Extensibility) - RFC 8701
/// Chrome/Edge usam GREASE para prevenir ossificação do protocolo TLS
/// 
/// GREASE values são ignorados por servers mas detectáveis por fingerprinting
pub struct GreaseGenerator;

impl GreaseGenerator {
    /// GREASE values reservados (RFC 8701)
    const GREASE_VALUES: &'static [u16] = &[
        0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a,
        0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
        0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
        0xcaca, 0xdada, 0xeaea, 0xfafa,
    ];

    /// Gera GREASE value aleatório
    pub fn generate() -> u16 {
        let mut rng = rand::thread_rng();
        *Self::GREASE_VALUES.choose(&mut rng).unwrap()
    }

    /// Gera múltiplos GREASE values únicos
    pub fn generate_multiple(count: usize) -> Vec<u16> {
        let mut rng = rand::thread_rng();
        let mut values: Vec<u16> = Self::GREASE_VALUES.to_vec();
        values.shuffle(&mut rng);
        values.into_iter().take(count).collect()
    }

    /// Verifica se value é GREASE
    pub fn is_grease(value: u16) -> bool {
        Self::GREASE_VALUES.contains(&value)
    }

    /// Injeta GREASE em lista de cipher suites (Chrome behavior)
    pub fn inject_in_cipher_suites(ciphers: &mut Vec<u16>) {
        let grease = Self::generate();
        // Chrome coloca GREASE como primeiro cipher
        ciphers.insert(0, grease);
    }

    /// Injeta GREASE em lista de extensions (Chrome behavior)
    pub fn inject_in_extensions(extensions: &mut Vec<u16>) {
        let grease = Self::generate();
        // Chrome coloca GREASE como primeira extension
        extensions.insert(0, grease);
    }

    /// Injeta GREASE em supported groups (curves)
    pub fn inject_in_groups(groups: &mut Vec<u16>) {
        let grease = Self::generate();
        groups.insert(0, grease);
    }
}

/// TLS Extension Randomizer
/// Randomiza ordem de extensões TLS para evitar fingerprinting estático
pub struct ExtensionRandomizer;

impl ExtensionRandomizer {
    /// Extensões obrigatórias que devem aparecer em ordem fixa
    const MANDATORY_EXTENSIONS: &'static [u16] = &[
        0x0000, // server_name
        0x000d, // signature_algorithms
        0x002b, // supported_versions
        0x0033, // key_share
    ];

    /// Verifica se extension é obrigatória
    fn is_mandatory(ext_id: u16) -> bool {
        Self::MANDATORY_EXTENSIONS.contains(&ext_id)
    }

    /// Randomiza ordem de extensões (preservando obrigatórias)
    pub fn randomize(extensions: &mut Vec<u16>) {
        let mut rng = rand::thread_rng();

        // Separar mandatory e optional
        let (mandatory, mut optional): (Vec<_>, Vec<_>) = extensions
            .drain(..)
            .partition(|&ext| Self::is_mandatory(ext));

        // Shuffle apenas opcionais
        optional.shuffle(&mut rng);

        // Reconstruir: mandatory primeiro, depois shuffled
        extensions.extend(mandatory);
        extensions.extend(optional);
    }

    /// Adiciona jitter temporal à ordem (micro-delays)
    pub async fn apply_temporal_jitter() {
        let jitter_us = rand::thread_rng().gen_range(0..100); // 0-100 microseconds
        tokio::time::sleep(tokio::time::Duration::from_micros(jitter_us)).await;
    }
}

/// JA3/JA4 String Builder com GREASE e randomization
pub struct Ja3Builder {
    tls_version: u16,
    cipher_suites: Vec<u16>,
    extensions: Vec<u16>,
    curves: Vec<u16>,
    ec_point_formats: Vec<u8>,
}

impl Default for Ja3Builder {
    fn default() -> Self {
        Self::new()
    }
}

impl Ja3Builder {
    pub fn new() -> Self {
        Self {
            tls_version: 0x0303, // TLS 1.2
            cipher_suites: Vec::new(),
            extensions: Vec::new(),
            curves: Vec::new(),
            ec_point_formats: vec![0],
        }
    }

    /// Adiciona GREASE e randomiza
    pub fn with_grease_and_randomization(mut self) -> Self {
        // Injetar GREASE
        GreaseGenerator::inject_in_cipher_suites(&mut self.cipher_suites);
        GreaseGenerator::inject_in_extensions(&mut self.extensions);
        GreaseGenerator::inject_in_groups(&mut self.curves);

        // Randomizar ordem de opcionais
        ExtensionRandomizer::randomize(&mut self.extensions);

        self
    }

    /// Constrói JA3 string
    pub fn build_ja3(&self) -> String {
        let ciphers_str = self.cipher_suites
            .iter()
            .filter(|&&c| !GreaseGenerator::is_grease(c))
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join("-");

        let extensions_str = self.extensions
            .iter()
            .filter(|&&e| !GreaseGenerator::is_grease(e))
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join("-");

        let curves_str = self.curves
            .iter()
            .filter(|&&g| !GreaseGenerator::is_grease(g))
            .map(|g| g.to_string())
            .collect::<Vec<_>>()
            .join("-");

        let ec_formats_str = self.ec_point_formats
            .iter()
            .map(|f| f.to_string())
            .collect::<Vec<_>>()
            .join("-");

        format!(
            "{},{},{},{},{}",
            self.tls_version,
            ciphers_str,
            extensions_str,
            curves_str,
            ec_formats_str
        )
    }

    /// Constrói JA4+ string (versão 2025)
    pub fn build_ja4_plus(&self) -> String {
        use sha2::{Sha256, Digest};

        let ver = match self.tls_version {
            0x0304 => "13",
            0x0303 => "12",
            0x0302 => "11",
            0x0301 => "10",
            _ => "00",
        };
        let protocol = format!("t{}", ver);

        // Hash de cipher suites
        let ciphers_hash = {
            let ciphers_str = self.cipher_suites
                .iter()
                .filter(|&&c| !GreaseGenerator::is_grease(c))
                .map(|c| format!("{:04x}", c))
                .collect::<Vec<_>>()
                .join(",");
            
            let mut hasher = Sha256::new();
            hasher.update(ciphers_str.as_bytes());
            let hash = hasher.finalize();
            hex::encode(&hash[..6]) // 12 chars
        };

        // Hash de extensions (ordem normalizada)
        let extensions_hash = {
            let mut ext_ids: Vec<_> = self.extensions
                .iter()
                .filter(|&&e| !GreaseGenerator::is_grease(e))
                .copied()
                .collect();
            ext_ids.sort(); // Normalizar

            let ext_str = ext_ids
                .iter()
                .map(|e| format!("{:04x}", e))
                .collect::<Vec<_>>()
                .join(",");

            let mut hasher = Sha256::new();
            hasher.update(ext_str.as_bytes());
            let hash = hasher.finalize();
            hex::encode(&hash[..6]) // 12 chars
        };

        format!("{}_{}_{}", protocol, ciphers_hash, extensions_hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_grease_generation() {
        let grease = GreaseGenerator::generate();
        assert!(GreaseGenerator::is_grease(grease));
    }

    #[test]
    fn test_grease_multiple_unique() {
        let greases = GreaseGenerator::generate_multiple(3);
        assert_eq!(greases.len(), 3);
        
        // Verificar que são únicos
        let unique: std::collections::HashSet<_> = greases.iter().collect();
        assert_eq!(unique.len(), 3);
    }

    #[test]
    fn test_inject_cipher_suites() {
        let mut ciphers = vec![0x1301, 0x1302, 0x1303];
        GreaseGenerator::inject_in_cipher_suites(&mut ciphers);
        
        assert_eq!(ciphers.len(), 4);
        assert!(GreaseGenerator::is_grease(ciphers[0]));
    }

    #[test]
    fn test_extension_randomization() {
        let mut extensions = vec![0x0000, 0x000d, 0x0010, 0x0023];
        ExtensionRandomizer::randomize(&mut extensions);
        
        // Mandatory devem estar presentes
        assert!(extensions.contains(&0x0000));
        assert!(extensions.contains(&0x000d));
    }

    #[test]
    fn test_ja3_with_grease() {
        let mut builder = Ja3Builder::new();
        builder.cipher_suites = vec![0x1301, 0x1302];
        builder.extensions = vec![0x0000, 0x0010];
        builder.curves = vec![0x001d, 0x0017];
        
        builder = builder.with_grease_and_randomization();
        
        let ja3 = builder.build_ja3();
        // GREASE deve ser filtrado no output
        assert!(!ja3.contains("2570")); // 0x0a0a em decimal
    }

    #[test]
    fn test_ja4_plus_format() {
        let mut builder = Ja3Builder::new();
        builder.cipher_suites = vec![0x1301, 0x1302];
        builder.extensions = vec![0x0000, 0x0010];
        
        let ja4 = builder.build_ja4_plus();
        
        // Formato: t{version}_{hash1}_{hash2}
        assert!(ja4.starts_with("t12"));
        assert_eq!(ja4.matches('_').count(), 2);
    }
}
