// Тестовая поддержка: парсер wire-фикстр Task 1 (формат testdata/wire/*.txt:
// `# контекст`-блоки, строки `TX <hex>` / `RX <hex>`, NOTE игнорируются —
// тот же контракт, что в mailbox.rs-тестах; один парсер на крейт вместо
// трёх копий).

pub(crate) struct WireBlock {
    pub ctx: String,
    pub tx: Vec<u8>,
    pub rx: Vec<u8>,
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
        .collect()
}

pub(crate) fn parse_wire(text: &str) -> Vec<WireBlock> {
    let mut blocks = Vec::new();
    let mut cur: Option<WireBlock> = None;
    for line in text.lines() {
        let line = line.trim();
        if let Some(ctx) = line.strip_prefix("# ") {
            if let Some(b) = cur.take() {
                blocks.push(b);
            }
            cur = Some(WireBlock {
                ctx: ctx.to_string(),
                tx: Vec::new(),
                rx: Vec::new(),
            });
            continue;
        }
        let Some(b) = cur.as_mut() else { continue };
        if let Some(hex) = line.strip_prefix("TX ") {
            b.tx = unhex(hex);
        } else if let Some(hex) = line.strip_prefix("RX ") {
            b.rx = unhex(hex);
        }
    }
    if let Some(b) = cur {
        blocks.push(b);
    }
    blocks
}

pub(crate) fn block<'a>(blocks: &'a [WireBlock], needle: &str) -> &'a WireBlock {
    blocks
        .iter()
        .find(|b| b.ctx.contains(needle))
        .unwrap_or_else(|| panic!("блок '{needle}' не найден"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tx_rx_pairs() {
        let blocks = parse_wire("# a\nTX 0102\nRX 0304\nNOTE x=1\n# b\nTX ff\n");
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0].tx, vec![0x01, 0x02]);
        assert_eq!(blocks[0].rx, vec![0x03, 0x04]);
        assert_eq!(blocks[1].tx, vec![0xff]);
        assert!(blocks[1].rx.is_empty());
    }
}
