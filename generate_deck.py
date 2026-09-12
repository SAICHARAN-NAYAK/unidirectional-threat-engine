"""
CYBERSHIELD High-Impact 5-Slide Enterprise Architecture Presentation Generator (V2 Visual Edition)
Embeds high-resolution visual diagrams, 3D hardware renderings, and live production screenshots:
- 16:9 widescreen layout
- Dark Obsidian / Tactical Cyber aesthetics
- 3D Isometric Data Diode Hardware Enclave
- Holographic MITRE Cyber Defense Command Center
- Live Production SOC Operations Dashboard & Wireshark Packet Dissector Screenshots
"""

import os
from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN
from pptx.enum.shapes import MSO_SHAPE

# Enterprise Cyber Palette
BG_DARK = RGBColor(11, 15, 25)       # #0B0F19 Obsidian
PANEL_BG = RGBColor(17, 24, 39)     # #111827 Deep Slate
CARD_BG = RGBColor(23, 33, 53)       # #172135 Elevated Card
ACCENT_CYAN = RGBColor(0, 229, 255)  # #00E5FF Neon Cyber Cyan
ACCENT_BLUE = RGBColor(59, 130, 246) # #3B82F6 Electric Blue
ACCENT_RED = RGBColor(255, 71, 87)   # #FF4757 Threat Crimson
ACCENT_GREEN = RGBColor(16, 185, 129)# #10B981 Verified Emerald
ACCENT_AMBER = RGBColor(245, 158, 11)# #F59E0B Warning Amber
TEXT_WHITE = RGBColor(243, 244, 246) # #F3F4F6 Crisp White
TEXT_MUTED = RGBColor(156, 163, 175) # #9CA3AF Cool Gray
BORDER_COLOR = RGBColor(37, 50, 78)  # Card subtle outline

ASSETS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web", "static", "assets")

def set_slide_background(slide):
    background = slide.background
    fill = background.fill
    fill.solid()
    fill.fore_color.rgb = BG_DARK

def add_header(slide, tag_text: str, title_text: str, subtitle_text: str):
    """Adds standardized, sleek cybersecurity slide header."""
    tag_box = slide.shapes.add_textbox(Inches(0.8), Inches(0.4), Inches(5.5), Inches(0.32))
    tf_tag = tag_box.text_frame
    tf_tag.word_wrap = True
    p_tag = tf_tag.paragraphs[0]
    p_tag.text = tag_text.upper()
    p_tag.font.size = Pt(10)
    p_tag.font.bold = True
    p_tag.font.color.rgb = ACCENT_CYAN

    title_box = slide.shapes.add_textbox(Inches(0.8), Inches(0.68), Inches(11.7), Inches(0.55))
    tf_title = title_box.text_frame
    tf_title.word_wrap = True
    p_title = tf_title.paragraphs[0]
    p_title.text = title_text
    p_title.font.size = Pt(21)
    p_title.font.bold = True
    p_title.font.color.rgb = TEXT_WHITE

    sub_box = slide.shapes.add_textbox(Inches(0.8), Inches(1.2), Inches(11.7), Inches(0.35))
    tf_sub = sub_box.text_frame
    tf_sub.word_wrap = True
    p_sub = tf_sub.paragraphs[0]
    p_sub.text = subtitle_text
    p_sub.font.size = Pt(11.5)
    p_sub.font.color.rgb = TEXT_MUTED

def add_card(slide, left, top, width, height, title, body_bullets, accent_color=ACCENT_CYAN, border=BORDER_COLOR):
    """Draws a themed card container with title and bullet points."""
    shape = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, left, top, width, height)
    shape.fill.solid()
    shape.fill.fore_color.rgb = CARD_BG
    shape.line.color.rgb = border
    shape.line.width = Pt(1.2)

    tb = slide.shapes.add_textbox(left + Inches(0.14), top + Inches(0.1), width - Inches(0.28), height - Inches(0.2))
    tf = tb.text_frame
    tf.word_wrap = True

    p0 = tf.paragraphs[0]
    p0.text = title
    p0.font.size = Pt(13)
    p0.font.bold = True
    p0.font.color.rgb = accent_color
    p0.space_after = Pt(4)

    for bullet in body_bullets:
        p = tf.add_paragraph()
        p.text = bullet
        p.font.size = Pt(10)
        p.font.color.rgb = TEXT_WHITE
        p.space_after = Pt(3)
        p.level = 0

def add_image_card(slide, img_name: str, left, top, width, height, caption: str = ""):
    """Embeds an image inside a stylized cybersecurity card with neon borders."""
    img_path = os.path.join(ASSETS_DIR, img_name)
    if not os.path.exists(img_path):
        return

    # Background frame
    frame = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, left, top, width, height)
    frame.fill.solid()
    frame.fill.fore_color.rgb = PANEL_BG
    frame.line.color.rgb = ACCENT_CYAN
    frame.line.width = Pt(1.2)

    # Image slightly inset
    pad = Inches(0.08)
    slide.shapes.add_picture(img_path, left + pad, top + pad, width - (2 * pad), height - (Inches(0.35) if caption else (2 * pad)))

    if caption:
        cap_box = slide.shapes.add_textbox(left, top + height - Inches(0.32), width, Inches(0.3))
        tf_c = cap_box.text_frame
        p_c = tf_c.paragraphs[0]
        p_c.text = caption.upper()
        p_c.font.size = Pt(8.5)
        p_c.font.bold = True
        p_c.font.color.rgb = ACCENT_CYAN
        p_c.alignment = PP_ALIGN.CENTER

def build_presentation(output_path: str = "CYBERSHIELD_Architecture_Deck.pptx"):
    prs = Presentation()
    prs.slide_width = Inches(13.333)
    prs.slide_height = Inches(7.5)
    blank_layout = prs.slide_layouts[6]

    # =========================================================================
    # SLIDE 1: Executive Title & Mission (With Holographic SOC Center Visual)
    # =========================================================================
    s1 = prs.slides.add_slide(blank_layout)
    set_slide_background(s1)

    # Top Badge
    badge = s1.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), Inches(0.7), Inches(3.4), Inches(0.35))
    badge.fill.solid()
    badge.fill.fore_color.rgb = PANEL_BG
    badge.line.color.rgb = ACCENT_CYAN
    tb_b = badge.text_frame
    p_b = tb_b.paragraphs[0]
    p_b.text = "AIR-GAPPED DATA DIODE ENCLAVE v2.4"
    p_b.font.size = Pt(10)
    p_b.font.bold = True
    p_b.font.color.rgb = ACCENT_CYAN
    p_b.alignment = PP_ALIGN.CENTER

    # Left Side: Hero Text
    hero_box = s1.shapes.add_textbox(Inches(0.8), Inches(1.15), Inches(5.8), Inches(1.5))
    tf_hero = hero_box.text_frame
    tf_hero.word_wrap = True
    p_h1 = tf_hero.paragraphs[0]
    p_h1.text = "CYBERSHIELD"
    p_h1.font.size = Pt(42)
    p_h1.font.bold = True
    p_h1.font.color.rgb = TEXT_WHITE
    
    p_h2 = tf_hero.add_paragraph()
    p_h2.text = "Unidirectional Threat Detection Engine"
    p_h2.font.size = Pt(18)
    p_h2.font.bold = True
    p_h2.font.color.rgb = ACCENT_CYAN

    desc_box = s1.shapes.add_textbox(Inches(0.8), Inches(2.7), Inches(5.8), Inches(1.1))
    tf_desc = desc_box.text_frame
    tf_desc.word_wrap = True
    p_d = tf_desc.paragraphs[0]
    p_d.text = (
        "High-performance passive cyber threat attribution operating over physical data diodes at 50,000+ packets/sec. "
        "Engineered with 16-shard zero-contention partitioning, statistical AI anomaly detection, and automated containment."
    )
    p_d.font.size = Pt(12)
    p_d.font.color.rgb = TEXT_MUTED

    # Right Side: Huge 3D Holographic SOC Center Visual
    add_image_card(
        s1,
        "mitre_cyber_center.jpg",
        Inches(6.8),
        Inches(0.8),
        Inches(5.73),
        Inches(3.4),
        "3D Holographic Cyber Defense Operations Command Enclave"
    )

    # 4 Bottom Cards
    pillars = [
        ("OPTICAL DIODE ISOLATION", [
            "• Physical Tx severed (Rx = 1)",
            "• Mathematical stealth guarantee",
            "• Zero backchannel exploitation",
            "• Air-gapped boundary defense"
        ], ACCENT_CYAN),
        ("16-SHARD INGRESS", [
            "• 50,000+ pps sustained ingress",
            "• Lock-free micro-batch routing",
            "• Zero-allocation __slots__ model",
            "• Sub-110ms sliding window SLA"
        ], ACCENT_BLUE),
        ("AUTONOMOUS AI & MITRE", [
            "• 14 enterprise tactics mapped",
            "• C2 beacon detection (CV < 0.15)",
            "• Fast Shannon entropy (>3.65)",
            "• Dynamic multi-firewall synthesis"
        ], ACCENT_AMBER),
        ("CROSS-PLATFORM SOC", [
            "• Real-time WebSocket stream",
            "• Live Cloudflare HTTPS tunnel",
            "• Permanent 24/7 GitHub Pages",
            "• Native Android Studio WebView"
        ], ACCENT_GREEN),
    ]

    card_w = Inches(2.78)
    card_gap = Inches(0.19)
    top_y = Inches(4.4)
    h_y = Inches(2.6)

    for i, (p_title, p_bullets, p_col) in enumerate(pillars):
        add_card(s1, Inches(0.8) + i * (card_w + card_gap), top_y, card_w, h_y, p_title, p_bullets, p_col)

    # =========================================================================
    # SLIDE 2: Ingestion Pipeline (With 3D Data Diode Hardware Render)
    # =========================================================================
    s2 = prs.slides.add_slide(blank_layout)
    set_slide_background(s2)
    add_header(
        s2,
        "CORE ARCHITECTURE & INGESTION PIPELINE",
        "16-Shard Hash Partitioning & High-Throughput Stream Pipeline",
        "Hardware optical diode isolation feeding micro-batched, lock-partitioned analytical queues."
    )

    # Flowchart Blocks Across Top
    stages = [
        ("1. PHYSICAL INGRESS", "Mirror TAP / SPAN\nOptical Diode Rx\nTx = 0 Physical Cut", ACCENT_CYAN),
        ("2. BINARY PARSER", "Zero-Copy PCAP Unpack\nIPv4 / IPv6 Wire Decode\nTCP Flags & Raw UDP", ACCENT_BLUE),
        ("3. MICRO-BATCHER", "Batch Size: 250 pkts\nHash Routing Function:\n(hash(src) & 0x7F) % 16", ACCENT_AMBER),
        ("4. 16 SHARD CORES", "16 Independent Locks\nRing Buffers (maxlen=250)\nZero Global Contention", ACCENT_CYAN),
        ("5. ROLLING PRUNER", "3.0s Sliding Window\nO(1) Popleft Eviction\nSub-110ms Triage SLA", ACCENT_GREEN),
    ]

    fw = Inches(2.2)
    fgap = Inches(0.2)
    fy = Inches(1.65)
    fh = Inches(1.25)

    for j, (st_t, st_b, st_c) in enumerate(stages):
        box = s2.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8) + j * (fw + fgap), fy, fw, fh)
        box.fill.solid()
        box.fill.fore_color.rgb = PANEL_BG
        box.line.color.rgb = st_c
        box.line.width = Pt(1.5)
        
        tf_s = box.text_frame
        tf_s.word_wrap = True
        p_st0 = tf_s.paragraphs[0]
        p_st0.text = st_t
        p_st0.font.size = Pt(10)
        p_st0.font.bold = True
        p_st0.font.color.rgb = st_c
        p_st0.alignment = PP_ALIGN.CENTER
        
        p_st1 = tf_s.add_paragraph()
        p_st1.text = st_b
        p_st1.font.size = Pt(9)
        p_st1.font.color.rgb = TEXT_WHITE
        p_st1.alignment = PP_ALIGN.CENTER

        if j < len(stages) - 1:
            arrow = s2.shapes.add_shape(
                MSO_SHAPE.RIGHT_ARROW,
                Inches(0.8) + j * (fw + fgap) + fw + Inches(0.04),
                fy + Inches(0.48),
                Inches(0.12),
                Inches(0.22)
            )
            arrow.fill.solid()
            arrow.fill.fore_color.rgb = ACCENT_CYAN
            arrow.line.fill.background()

    # Left: 3D Isometric Optical Data Diode Hardware Render
    add_image_card(
        s2,
        "data_diode_hardware.jpg",
        Inches(0.8),
        Inches(3.1),
        Inches(5.72),
        Inches(3.9),
        "Physical Optical Data Diode Network TAP (Tx Severed / Rx Listen-Only)"
    )

    # Right: 2 Architecture Deep-Dive Cards
    add_card(
        s2, Inches(6.8), Inches(3.1), Inches(5.73), Inches(1.85),
        "ZERO-CONTENTION CONCURRENCY",
        [
            "• Lock Partitioning: Divides state into 16 discrete EnclaveShard instances.",
            "• Lock Amortization: Groups micro-batches by target shard prior to lock acquisition.",
            "• Throughput: Sustained 25,000–50,000+ pps on commodity CPU cores without frame drops."
        ],
        ACCENT_CYAN
    )

    add_card(
        s2, Inches(6.8), Inches(5.15), Inches(5.73), Inches(1.85),
        "LOW-ALLOCATION MEMORY & STEALTH",
        [
            "• Python __slots__ Optimization: Eliminates dynamic dictionary allocation overhead.",
            "• Bounded Ring Buffers: In-memory sliding windows prevent memory leaks under surges.",
            "• Passive Stealth: Zero TCP RST or ICMP packets emitted back onto monitored wire."
        ],
        ACCENT_GREEN
    )

    # =========================================================================
    # SLIDE 3: Mathematical Detection Engine (With Wireshark Dissector Visual)
    # =========================================================================
    s3 = prs.slides.add_slide(blank_layout)
    set_slide_background(s3)
    add_header(
        s3,
        "ANALYTICAL CORE & MATHEMATICAL FORMULATIONS",
        "Mathematical Threat Detection: AI/ML, Entropy & JA4 Fingerprinting",
        "Deterministic models operating concurrently across sliding windows for precision threat attribution."
    )

    # Left Column: 2 Analytical Formulations Cards
    add_card(
        s3, Inches(0.8), Inches(1.65), Inches(5.72), Inches(2.65),
        "1. BOTNET C2 BEACONING (IAT & CV)",
        [
            "• Theory: Automated implants maintain rhythmic callbacks; human traffic is chaotic.",
            "• Formula: CV = σ / μ  (where μ = mean interval, σ = standard deviation of deltas).",
            "• Detection Boundary: CV < 0.15 identifies automated heartbeat periodicity.",
            "• Confidence Model: Score = min(0.99, 1.0 - CV)."
        ],
        ACCENT_AMBER
    )

    add_card(
        s3, Inches(0.8), Inches(4.45), Inches(5.72), Inches(2.65),
        "2. DNS TUNNELING & DGA (FAST SHANNON ENTROPY)",
        [
            "• Theory: Base32/64 exfiltration payloads pack high information density into subdomains.",
            "• Formula: H(X) = log2(L) - (1/L) * Σ count(c) * log2(count(c)).",
            "• Table Cache: Accelerated via pre-computed _LOG2_CACHE[k] lookup table in O(N).",
            "• Boundary: H(X) > 3.65 indicates encoded data tunneling or DGA rendezvous."
        ],
        ACCENT_RED
    )

    # Right: Live Wireshark-Style Packet Dissector Screenshot
    add_image_card(
        s3,
        "packet_dissector.png",
        Inches(6.8),
        Inches(1.65),
        Inches(5.73),
        Inches(3.3),
        "Live Deep Packet Dissector (Wireshark-Style Protocol Breakdown)"
    )

    # Right Bottom: JA4 TLS Client Fingerprinting Card
    add_card(
        s3, Inches(6.8), Inches(5.1), Inches(5.73), Inches(2.0),
        "3. JA4 TLS FINGERPRINTING & VOLUMETRIC SYN FLOOD",
        [
            "• JA4 RFC 8701: Strips GREASE ciphers; SHA-256 hashes of sorted ciphers and extensions.",
            "• Signature Match: Identifies Cobalt Strike Malleable C2 profile over encrypted TLS.",
            "• Volumetric SYN Flood: >75% SYN ratio in rolling window triggers P0 mitigation."
        ],
        ACCENT_CYAN
    )

    # =========================================================================
    # SLIDE 4: Autonomous AI Triage & MITRE ATT&CK (With Matrix Screenshot)
    # =========================================================================
    s4 = prs.slides.add_slide(blank_layout)
    set_slide_background(s4)
    add_header(
        s4,
        "AUTONOMOUS AI SECURITY & CONTAINMENT",
        "MITRE ATT&CK Enterprise Matrix & Automated Firewall Synthesis",
        "Deterministic correlation, blast radius modeling, and instant multi-platform rule generation."
    )

    # Left: Production Screenshot of MITRE ATT&CK Matrix View
    add_image_card(
        s4,
        "mitre_matrix.png",
        Inches(0.8),
        Inches(1.65),
        Inches(5.72),
        Inches(3.45),
        "Verified MITRE ATT&CK Enterprise Matrix (14 Active Tactics)"
    )

    # Left Bottom: Blast Radius & Merkle Audit Card
    add_card(
        s4, Inches(0.8), Inches(5.25), Inches(5.72), Inches(1.85),
        "BLAST RADIUS & MERKLE AUDIT LEDGER",
        [
            "• Topology-Aware Risk: Evaluates exposure across Domain Controllers and DBs.",
            "• Merkle Hash-Chaining: Sequential SHA-256 ledger guarantees immutable audit trail.",
            "• LLM Triage Hook: Optional Gemini API integration for semantic incident reporting."
        ],
        ACCENT_AMBER
    )

    # Right: Production Screenshot of Mitigation Rules View
    add_image_card(
        s4,
        "mitigation_rules.png",
        Inches(6.8),
        Inches(1.65),
        Inches(5.73),
        Inches(3.45),
        "Live Dynamic Firewall & IDS Rule Synthesizer (5 Formats)"
    )

    # Right Bottom: Rule Synthesis Code Box
    add_card(
        s4, Inches(6.8), Inches(5.25), Inches(5.73), Inches(1.85),
        "AUTOMATED RULE SYNTHESIS EXPORTS",
        [
            "• Linux IPTables: iptables -A INPUT -p tcp --dport 443 -m hashlimit --hashlimit-above 50/sec -j DROP",
            "• Linux NFTables: table inet filter { chain input { tcp flags syn meter ... drop } }",
            "• Suricata / Snort IDS: alert tcp any any -> $DST $PORT (msg:\"CYBERSHIELD Flood\"; sid:2000001;)"
        ],
        ACCENT_GREEN
    )

    # =========================================================================
    # SLIDE 5: Web SOC Console & Global Deployment (With Full Live Dashboard)
    # =========================================================================
    s5 = prs.slides.add_slide(blank_layout)
    set_slide_background(s5)
    add_header(
        s5,
        "ENTERPRISE OPERATIONS & GLOBAL DEPLOYMENT",
        "Web SOC Operations Console & Multi-Platform Delivery",
        "Accessible globally over HTTPS, permanent edge hosting, and native Android Studio integration."
    )

    # Left: Huge Hero Screenshot of Live CYBERSHIELD Dashboard with Radar
    add_image_card(
        s5,
        "soc_dashboard_live.png",
        Inches(0.8),
        Inches(1.65),
        Inches(6.6),
        Inches(5.45),
        "Live Operations Console: Optical Threat Radar, Ingest Metrics & Authentic Stream"
    )

    # Right Column: 3 Deployment Cards
    add_card(
        s5, Inches(7.6), Inches(1.65), Inches(4.93), Inches(1.7),
        "GLOBAL HTTPS CLOUDFLARE TUNNEL",
        [
            "• Live Worldwide Link: https://red-avi-object-email.trycloudflare.com",
            "• Zero-Barrier Access: No firewall port forwarding or public IP exposure.",
            "• Interactive Threat Injection: Trigger live SYN floods & C2 beacon pulses."
        ],
        ACCENT_GREEN
    )

    add_card(
        s5, Inches(7.6), Inches(3.5), Inches(4.93), Inches(1.7),
        "PERMANENT EDGE WEB (GITHUB PAGES)",
        [
            "• Permanent 24/7 Hosting: https://saicharan-nayak.github.io/unidirectional-threat-engine/",
            "• Autonomous Dual-Mode: Seamless WebSocket or client simulation fallback.",
            "• Automated CI/CD: Deployed automatically via GitHub Actions on push."
        ],
        ACCENT_BLUE
    )

    add_card(
        s5, Inches(7.6), Inches(5.35), Inches(4.93), Inches(1.75),
        "ANDROID STUDIO APP & SIEM",
        [
            "• Native Android App: android_studio_app/ WebView wrapper with touch HUD.",
            "• One-Click Launcher: Open_In_Android_Studio.bat auto-detects active IDE.",
            "• SIEM Integrations: Background worker exporting ArcSight CEF and Syslog."
        ],
        ACCENT_AMBER
    )

    prs.save(output_path)
    print(f"[+] Successfully generated visual PowerPoint presentation: {output_path}")

if __name__ == "__main__":
    build_presentation()
