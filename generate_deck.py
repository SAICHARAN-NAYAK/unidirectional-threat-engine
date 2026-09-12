"""
CYBERSHIELD High-Impact 5-Slide Enterprise Architecture Presentation Generator
Generates a professional, beautifully styled PowerPoint (.pptx) file with:
- Dark Obsidian / Tactical Cyber aesthetics
- 16:9 widescreen layout
- Architecture flowcharts and pipeline blocks
- AI/ML mathematical formulas and detection models
- MITRE ATT&CK and firewall rule synthesis diagrams
- Multi-platform and live deployment topologies
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

def set_slide_background(slide):
    background = slide.background
    fill = background.fill
    fill.solid()
    fill.fore_color.rgb = BG_DARK

def add_header(slide, tag_text: str, title_text: str, subtitle_text: str):
    """Adds standardized, sleek cybersecurity slide header."""
    # Tag Pill
    tag_box = slide.shapes.add_textbox(Inches(0.8), Inches(0.4), Inches(4.5), Inches(0.35))
    tf_tag = tag_box.text_frame
    tf_tag.word_wrap = True
    p_tag = tf_tag.paragraphs[0]
    p_tag.text = tag_text.upper()
    p_tag.font.size = Pt(10)
    p_tag.font.bold = True
    p_tag.font.color.rgb = ACCENT_CYAN

    # Main Title
    title_box = slide.shapes.add_textbox(Inches(0.8), Inches(0.7), Inches(11.7), Inches(0.6))
    tf_title = title_box.text_frame
    tf_title.word_wrap = True
    p_title = tf_title.paragraphs[0]
    p_title.text = title_text
    p_title.font.size = Pt(22)
    p_title.font.bold = True
    p_title.font.color.rgb = TEXT_WHITE

    # Subtitle
    sub_box = slide.shapes.add_textbox(Inches(0.8), Inches(1.25), Inches(11.7), Inches(0.4))
    tf_sub = sub_box.text_frame
    tf_sub.word_wrap = True
    p_sub = tf_sub.paragraphs[0]
    p_sub.text = subtitle_text
    p_sub.font.size = Pt(12)
    p_sub.font.color.rgb = TEXT_MUTED

def add_card(slide, left, top, width, height, title, body_bullets, accent_color=ACCENT_CYAN, border=BORDER_COLOR):
    """Draws a themed card container with title and bullet points."""
    shape = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, left, top, width, height)
    shape.fill.solid()
    shape.fill.fore_color.rgb = CARD_BG
    shape.line.color.rgb = border
    shape.line.width = Pt(1.2)

    tb = slide.shapes.add_textbox(left + Inches(0.15), top + Inches(0.12), width - Inches(0.3), height - Inches(0.24))
    tf = tb.text_frame
    tf.word_wrap = True

    p0 = tf.paragraphs[0]
    p0.text = title
    p0.font.size = Pt(14)
    p0.font.bold = True
    p0.font.color.rgb = accent_color
    p0.space_after = Pt(6)

    for bullet in body_bullets:
        p = tf.add_paragraph()
        p.text = bullet
        p.font.size = Pt(11)
        p.font.color.rgb = TEXT_WHITE
        p.space_after = Pt(4)
        p.level = 0

def build_presentation(output_path: str = "CYBERSHIELD_Architecture_Deck.pptx"):
    prs = Presentation()
    # 16:9 Widescreen standard
    prs.slide_width = Inches(13.333)
    prs.slide_height = Inches(7.5)
    blank_layout = prs.slide_layouts[6]

    # =========================================================================
    # SLIDE 1: Executive Title & High-Level Mission
    # =========================================================================
    s1 = prs.slides.add_slide(blank_layout)
    set_slide_background(s1)

    # Big Top Badge
    badge = s1.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), Inches(0.8), Inches(3.2), Inches(0.38))
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

    # Hero Title
    hero_box = s1.shapes.add_textbox(Inches(0.8), Inches(1.35), Inches(11.7), Inches(1.4))
    tf_hero = hero_box.text_frame
    tf_hero.word_wrap = True
    p_h1 = tf_hero.paragraphs[0]
    p_h1.text = "CYBERSHIELD"
    p_h1.font.size = Pt(44)
    p_h1.font.bold = True
    p_h1.font.color.rgb = TEXT_WHITE
    
    p_h2 = tf_hero.add_paragraph()
    p_h2.text = "Unidirectional Threat Detection Engine & Enterprise Web SOC"
    p_h2.font.size = Pt(20)
    p_h2.font.bold = True
    p_h2.font.color.rgb = ACCENT_CYAN

    # Mission Statement Subtitle
    desc_box = s1.shapes.add_textbox(Inches(0.8), Inches(2.9), Inches(11.7), Inches(0.7))
    tf_desc = desc_box.text_frame
    tf_desc.word_wrap = True
    p_d = tf_desc.paragraphs[0]
    p_d.text = (
        "High-performance passive cyber threat attribution operating over physical data diodes at 50,000+ packets/sec. "
        "Engineered with 16-shard zero-contention partitioning, statistical AI anomaly detection, and automated containment."
    )
    p_d.font.size = Pt(13)
    p_d.font.color.rgb = TEXT_MUTED

    # 4 Key Pillars Cards
    pillars = [
        ("OPTICAL DIODE ISOLATION", [
            "• Physical Tx Disabled (Rx = 1)",
            "• Mathematical stealth guarantee",
            "• Zero backchannel exploitation",
            "• Air-gapped boundary defense"
        ], ACCENT_CYAN),
        ("16-SHARD HASH PARTITIONING", [
            "• 50,000+ pps sustained ingress",
            "• Lock-free micro-batch routing",
            "• Zero-allocation __slots__ memory",
            "• Sub-110ms sliding window SLA"
        ], ACCENT_BLUE),
        ("AUTONOMOUS AI & MITRE", [
            "• 14 enterprise tactics mapped",
            "• C2 beacon detection (CV < 0.15)",
            "• Fast Shannon entropy (>3.65)",
            "• Dynamic multi-firewall synthesis"
        ], ACCENT_AMBER),
        ("MULTI-PLATFORM SOC", [
            "• Real-time WebSocket stream",
            "• Live Cloudflare HTTPS tunnel",
            "• Permanent 24/7 GitHub Pages",
            "• Native Android Studio WebView"
        ], ACCENT_GREEN),
    ]

    card_w = Inches(2.78)
    card_gap = Inches(0.19)
    top_y = Inches(3.8)
    h_y = Inches(3.0)

    for i, (p_title, p_bullets, p_col) in enumerate(pillars):
        add_card(s1, Inches(0.8) + i * (card_w + card_gap), top_y, card_w, h_y, p_title, p_bullets, p_col)

    # =========================================================================
    # SLIDE 2: Ingestion Pipeline & 16-Shard Concurrency Architecture
    # =========================================================================
    s2 = prs.slides.add_slide(blank_layout)
    set_slide_background(s2)
    add_header(
        s2,
        "CORE ARCHITECTURE & INGESTION PIPELINE",
        "16-Shard Hash Partitioning & High-Throughput Stream Pipeline",
        "Hardware optical diode isolation feeding micro-batched, lock-partitioned analytical queues."
    )

    # Flowchart Blocks Across the Middle
    stages = [
        ("1. PHYSICAL INGRESS", "Network TAP / SPAN\nOptical Fiber Diode\nTx = 0 / Rx = 1 Only", ACCENT_CYAN),
        ("2. BINARY PARSER", "Zero-Copy PCAP Unpack\nIPv4 / IPv6 Header\nTCP Flags & Raw UDP", ACCENT_BLUE),
        ("3. MICRO-BATCHING", "Batch Size: 250 pkts\nHash Routing Function:\n(hash(src) & 0x7F) % 16", ACCENT_AMBER),
        ("4. 16 SHARD CORES", "16 Independent Locks\nRing Buffers (maxlen=250)\nZero Global Contention", ACCENT_CYAN),
        ("5. ROLLING PRUNER", "3.0s Sliding Window\nO(1) Popleft Eviction\nSub-110ms Triage Loop", ACCENT_GREEN),
    ]

    fw = Inches(2.2)
    fgap = Inches(0.2)
    fy = Inches(1.85)
    fh = Inches(1.4)

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
        p_st0.font.size = Pt(11)
        p_st0.font.bold = True
        p_st0.font.color.rgb = st_c
        p_st0.alignment = PP_ALIGN.CENTER
        
        p_st1 = tf_s.add_paragraph()
        p_st1.text = st_b
        p_st1.font.size = Pt(9.5)
        p_st1.font.color.rgb = TEXT_WHITE
        p_st1.alignment = PP_ALIGN.CENTER

        # Add connector arrow between blocks
        if j < len(stages) - 1:
            arrow = s2.shapes.add_shape(
                MSO_SHAPE.RIGHT_ARROW,
                Inches(0.8) + j * (fw + fgap) + fw + Inches(0.04),
                fy + Inches(0.55),
                Inches(0.12),
                Inches(0.25)
            )
            arrow.fill.solid()
            arrow.fill.fore_color.rgb = ACCENT_CYAN
            arrow.line.fill.background()

    # 3 Deep Dive Lower Architecture Cards
    add_card(
        s2, Inches(0.8), Inches(3.55), Inches(3.75), Inches(3.4),
        "ZERO-CONTENTION CONCURRENCY",
        [
            "• Lock Partitioning: Divides state into 16 discrete EnclaveShard instances.",
            "• Lock Amortization: Groups micro-batches by target shard prior to acquisition, reducing lock requests from O(B) to O(16).",
            "• Benchmarked Throughput: Sustained 25,000–50,000+ pps on commodity CPU cores without dropped frames."
        ],
        ACCENT_CYAN
    )

    add_card(
        s2, Inches(4.78), Inches(3.55), Inches(3.75), Inches(3.4),
        "LOW-ALLOCATION MEMORY MODEL",
        [
            "• Python __slots__ Optimization: Structs PacketMetadata and ThreatAlert eliminate dynamic dictionary overhead.",
            "• Bounded Deques: In-memory sliding windows (maxlen=250) prevent memory leaks under multi-million packet surges.",
            "• Zero Garbage Collection Spikes: Predictable sub-millisecond execution SLAs."
        ],
        ACCENT_BLUE
    )

    add_card(
        s2, Inches(8.76), Inches(3.55), Inches(3.75), Inches(3.4),
        "UNIDIRECTIONAL DIODE GUARANTEE",
        [
            "• Physical Optical TAP: Monitored interface laser transmitter physically cut; receive fiber strictly isolated.",
            "• Passive Packet Dissection: Zero TCP RST or ICMP responses emitted back onto the customer network.",
            "• Complete Stealth: Adversaries cannot detect or target the monitoring sensor enclave."
        ],
        ACCENT_GREEN
    )

    # =========================================================================
    # SLIDE 3: Mathematical Detection Engine: AI/ML & Cryptographic Models
    # =========================================================================
    s3 = prs.slides.add_slide(blank_layout)
    set_slide_background(s3)
    add_header(
        s3,
        "ANALYTICAL CORE & MATHEMATICAL FORMULATIONS",
        "Algorithmic Threat Detection: Statistical, Entropy & Fingerprinting",
        "Deterministic models operating in parallel across sliding windows for precision threat attribution."
    )

    det_w = Inches(5.72)
    det_h = Inches(2.55)

    # Quadrant 1: C2 Beaconing (Statistical Dispersion)
    add_card(
        s3, Inches(0.8), Inches(1.8), det_w, det_h,
        "1. BOTNET C2 BEACONING (INTER-ARRIVAL TIME & CV)",
        [
            "• Theory: Automated implants maintain rhythmic callbacks; human traffic is chaotic.",
            "• Formula: CV = σ / μ  (where μ = mean interval, σ = standard deviation of arrival deltas).",
            "• Detection Threshold: CV < 0.15 indicates automated heartbeat periodicity (Cobalt Strike / Sliver).",
            "• Confidence Model: Score = min(0.99, 1.0 - CV)."
        ],
        ACCENT_AMBER
    )

    # Quadrant 2: Fast Shannon Entropy (DNS Exfiltration & DGA)
    add_card(
        s3, Inches(6.8), Inches(1.8), det_w, det_h,
        "2. DNS TUNNELING & DGA EXFILTRATION (SHANNON ENTROPY)",
        [
            "• Theory: Base32/64 exfiltration and algorithmically generated domains exhibit high entropy.",
            "• Formula: H(X) = log2(L) - (1/L) * Σ count(c) * log2(count(c)).",
            "• Hardware Acceleration: Accelerated via pre-computed _LOG2_CACHE[k] lookup table (O(N)).",
            "• Detection Boundary: H(X) > 3.65 indicates encoded data tunneling or DGA rendezvous."
        ],
        ACCENT_RED
    )

    # Quadrant 3: JA4 TLS Client Cryptographic Fingerprinting
    add_card(
        s3, Inches(0.8), Inches(4.55), det_w, det_h,
        "3. JA4 TLS CLIENT FINGERPRINTING (RFC 8701)",
        [
            "• Theory: Identifies offensive C2 frameworks (Cobalt Strike, Meterpreter) over HTTPS.",
            "• RFC 8701 GREASE Stripping: Bitmask (val & 0x0F0F) == 0x0A0A eliminates browser noise.",
            "• Canonical String: JA4_A (Proto_Ver_SNI_Ciphers_ALPN) + JA4_B (Cipher SHA-256) + JA4_C (Ext SHA-256).",
            "• Example: t13d1516h2_8daaf6152771_be40b441a884 matches Cobalt Strike Malleable C2 profile."
        ],
        ACCENT_CYAN
    )

    # Quadrant 4: Volumetric & Port Reconnaissance Fanout
    add_card(
        s3, Inches(6.8), Inches(4.55), det_w, det_h,
        "4. VOLUMETRIC SYN FLOOD & PORT RECON SCAN",
        [
            "• Volumetric Inundation: Multi-shard destination aggregation; >75% SYN ratio triggers instant P0 alert.",
            "• Port Reconnaissance Fanout: Cardinality tracking across (src_ip -> {dst_port}) in 3.0s window.",
            "• Dynamic Cardinality: Distinct ports >25 or targets >15 triggers horizontal/vertical scan alert.",
            "• Jitter Engine: Sub-second non-uniform timestamps eliminate artificial, robotic clock patterns."
        ],
        ACCENT_BLUE
    )

    # =========================================================================
    # SLIDE 4: Autonomous AI Incident Triage & Automated Containment
    # =========================================================================
    s4 = prs.slides.add_slide(blank_layout)
    set_slide_background(s4)
    add_header(
        s4,
        "AUTONOMOUS AI SECURITY & CONTAINMENT",
        "MITRE ATT&CK Enterprise Matrix & Automated Firewall Synthesis",
        "Deterministic correlation, blast radius modeling, and instant multi-platform rule generation."
    )

    # 3 Column Cards
    col_w = Inches(3.75)
    col_gap = Inches(0.23)
    c_top = Inches(1.8)
    c_h = Inches(5.15)

    add_card(
        s4, Inches(0.8), c_top, col_w, c_h,
        "MITRE ATT&CK ENCLAVE",
        [
            "• 14 Enterprise Tactics Mapped:",
            "  - Reconnaissance (TA0043)",
            "  - Initial Access (TA0001)",
            "  - Execution (TA0002)",
            "  - Defense Evasion (TA0005)",
            "  - Credential Access (TA0006)",
            "  - Discovery (TA0007)",
            "  - Command & Control (TA0011)",
            "  - Exfiltration (TA0010)",
            "  - Impact (TA0040)",
            "",
            "• Automated Technique Binding:",
            "  - T1498.001 (SYN Flood Exhaustion)",
            "  - T1071.001 (Web C2 Beaconing)",
            "  - T1046 (Port Recon Discovery)",
            "  - T1568.002 (Domain Generation DGA)",
            "  - T1573.002 (Asymmetric TLS C2)",
            "",
            "• Threat Actor Attribution:",
            "  Direct mapping to APT28, Mirai, Cobalt Strike, and LockBit affiliates."
        ],
        ACCENT_CYAN
    )

    add_card(
        s4, Inches(0.8) + col_w + col_gap, c_top, col_w, c_h,
        "BLAST RADIUS & PLAYBOOKS",
        [
            "• Topology-Aware Risk Scoring:",
            "  Evaluates target host sensitivity (Domain Controller, Database, Workstation).",
            "",
            "• Lateral Movement Modeling:",
            "  Calculates probability of attacker pivot across subnet boundaries.",
            "",
            "• Step-by-Step Playbook Generation:",
            "  - Step 1 (P0): Kernel SYN cookies / Host Isolation",
            "  - Step 2 (P1): Perimeter IP Drop / Route Blackhole",
            "  - Step 3 (P2): EDR memory dump & Kerberos token revocation",
            "",
            "• Cryptographic Merkle Audit Log:",
            "  Sequential SHA-256 hash-chaining prevents retroactive tampering of forensic logs.",
            "",
            "• Optional LLM Reasoning Hook:",
            "  Native support for Google Gemini API for natural language threat explanation."
        ],
        ACCENT_AMBER
    )

    add_card(
        s4, Inches(0.8) + 2 * (col_w + col_gap), c_top, col_w, c_h,
        "DYNAMIC RULE SYNTHESIS",
        [
            "Instant translation of alerts into 5 production-grade defense formats:",
            "",
            "1. Linux IPTables:",
            "   iptables -A INPUT -p tcp --dport 443 -m hashlimit --hashlimit-above 50/sec -j DROP",
            "",
            "2. Linux NFTables:",
            "   table inet filter { chain input { tcp flags syn meter syn-meter { ip saddr limit rate over 50/sec } drop } }",
            "",
            "3. Suricata IDS Rule:",
            "   alert tcp any any -> $DST $PORT (msg:\"CYBERSHIELD SYN Flood\"; flags:S; threshold:count 100, seconds 2; sid:2000001;)",
            "",
            "4. Snort 3 Network Rule:",
            "   drop tcp any any -> $DST $PORT (detection_filter:track by_dst, count 100, seconds 2; sid:3000001;)",
            "",
            "5. pfSense / OPNsense CLI:",
            "   pfsense-cli block host <ATTACKER_IP>"
        ],
        ACCENT_GREEN
    )

    # =========================================================================
    # SLIDE 5: Enterprise Web SOC Console, Multi-Platform & Deployment
    # =========================================================================
    s5 = prs.slides.add_slide(blank_layout)
    set_slide_background(s5)
    add_header(
        s5,
        "ENTERPRISE OPERATIONS & GLOBAL DEPLOYMENT",
        "Web SOC Operations Console & Multi-Platform Delivery",
        "Accessible globally over HTTPS, permanent edge hosting, and native Android Studio integration."
    )

    # 4 Architecture Deployment Cards
    dep_w = Inches(5.72)
    dep_h = Inches(2.55)

    add_card(
        s5, Inches(0.8), Inches(1.8), dep_w, dep_h,
        "ENTERPRISE WEB SOC CONSOLE",
        [
            "• Authentic Cyber Atmosphere: Dark obsidian UI, glassmorphic panels, and DEFCON status badge.",
            "• Non-Uniform Time Interleaving: Millisecond jitter timestamps break artificial looping patterns.",
            "• Corporate Asset Attribution: Maps raw IPs to enterprise DNS hostnames (wkst-*.corp, ad-dc01.corp).",
            "• Real-Time Threat Radar: SVG canvas visualizing live network ingress and fanout connections."
        ],
        ACCENT_CYAN
    )

    add_card(
        s5, Inches(6.8), Inches(1.8), dep_w, dep_h,
        "GLOBAL HTTPS CLOUDFLARE TUNNEL",
        [
            "• Worldwide Live URL: https://red-avi-object-email.trycloudflare.com",
            "• Zero-Barrier Access: No firewall port forwarding or public IP exposure required.",
            "• Real-Time Bi-Directional WebSocket: Sub-millisecond telemetry stream direct to any device.",
            "• Interactive Threat Injection: Trigger live SYN floods, C2 beacon pulses, and port recon scans."
        ],
        ACCENT_GREEN
    )

    add_card(
        s5, Inches(0.8), Inches(4.55), dep_w, dep_h,
        "PERMANENT EDGE WEB (GITHUB PAGES)",
        [
            "• Permanent 24/7 Hosting: https://saicharan-nayak.github.io/unidirectional-threat-engine/",
            "• Autonomous Dual-Mode: Automatically connects to live backend WebSocket if online.",
            "• Zero-Server Fallback: Auto-engages high-fidelity client-side simulation engine if offline.",
            "• Automated CI/CD: Deployed automatically via .github/workflows/deploy-pages.yml on push."
        ],
        ACCENT_BLUE
    )

    add_card(
        s5, Inches(6.8), Inches(4.55), dep_w, dep_h,
        "ANDROID STUDIO NATIVE APP & REPO",
        [
            "• Android Studio Project: android_studio_app/ native WebView wrapper with full touch controls.",
            "• One-Click Launcher: Open_In_Android_Studio.bat auto-detects active Android Studio executable.",
            "• SIEM Integrations: Background worker exporting ArcSight CEF, RFC 5424 Syslog, and Webhooks.",
            "• Open Source GitHub Repo: SAICHARAN-NAYAK/unidirectional-threat-engine (main branch)."
        ],
        ACCENT_AMBER
    )

    # Save Presentation
    prs.save(output_path)
    print(f"[+] Successfully generated enterprise PowerPoint presentation: {output_path}")

if __name__ == "__main__":
    build_presentation()
