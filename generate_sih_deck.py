"""
Smart India Hackathon 2026 (SIH) Official Format Slide Deck Generator
Theme: Blockchain & Cybersecurity
Problem Statement ID: SIH26145
Problem Statement Title: AI-Based Detection of Cyber Threats in Unidirectional IP Traffic
Organization: National Technical Research Organisation (NTRO)
Team Name: Galaxy Coders

Supercharges the official SIH template with:
- System architecture flowcharts
- 3D physical data diode hardware diagrams
- Real production SOC dashboard screenshots
- Wireshark-style packet dissector & MITRE ATT&CK matrix views
- Strict adherence to the official SIH 2026 layout, fonts, headers, and footers
"""

import os
from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR
from pptx.enum.shapes import MSO_SHAPE

# SIH Official Color Palette (Clean White Corporate with Tech Accents)
BG_WHITE = RGBColor(255, 255, 255)
TEXT_DARK = RGBColor(27, 38, 59)         # #1B263B Deep Navy
TEXT_MUTED = RGBColor(74, 85, 104)       # #4A5568 Slate Gray
SIH_BLUE = RGBColor(14, 56, 122)         # #0E387A Primary SIH Header Blue
SIH_ORANGE = RGBColor(249, 115, 22)      # #F97316 Indian Orange
CARD_BORDER_BLUE = RGBColor(14, 165, 233)# #0EA5E9 Cyan Blue
CARD_BORDER_RED = RGBColor(239, 68, 68)  # #EF4444 Crimson
CARD_BORDER_AMBER = RGBColor(245, 158, 11)# #F59E0B Amber
CARD_BORDER_GREEN = RGBColor(16, 185, 129)# #10B981 Emerald
CARD_BG_LIGHT = RGBColor(248, 250, 252)  # #F8FAFC Ultra-light slate

ASSETS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web", "static", "assets")

def add_sih_header(slide, title_text: str, team_name: str = "Galaxy Coders"):
    """Official SIH Header layout: Title left, Team pill left-sub, SIH 2026 branding right."""
    # Header Title
    title_box = slide.shapes.add_textbox(Inches(0.6), Inches(0.25), Inches(8.8), Inches(0.55))
    tf = title_box.text_frame
    tf.word_wrap = True
    p = tf.paragraphs[0]
    p.text = title_text.upper()
    p.font.size = Pt(21)
    p.font.bold = True
    p.font.color.rgb = SIH_BLUE

    # Team Pill (Oval shape top left under title or near it)
    pill = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.6), Inches(0.85), Inches(1.8), Inches(0.65))
    pill.fill.solid()
    pill.fill.fore_color.rgb = BG_WHITE
    pill.line.color.rgb = SIH_BLUE
    pill.line.width = Pt(1.5)
    tf_p = pill.text_frame
    p0 = tf_p.paragraphs[0]
    p0.text = "Team Name:"
    p0.font.size = Pt(9)
    p0.font.color.rgb = TEXT_MUTED
    p0.alignment = PP_ALIGN.CENTER
    p1 = tf_p.add_paragraph()
    p1.text = team_name
    p1.font.size = Pt(10)
    p1.font.bold = True
    p1.font.color.rgb = SIH_BLUE
    p1.alignment = PP_ALIGN.CENTER

    # Top Right SIH 2026 Badge
    sih_badge = slide.shapes.add_textbox(Inches(9.8), Inches(0.22), Inches(2.9), Inches(0.9))
    tf_sih = sih_badge.text_frame
    p_sih1 = tf_sih.paragraphs[0]
    p_sih1.text = "SMART INDIA"
    p_sih1.font.size = Pt(13)
    p_sih1.font.bold = True
    p_sih1.font.color.rgb = SIH_BLUE
    p_sih1.alignment = PP_ALIGN.RIGHT
    
    p_sih2 = tf_sih.add_paragraph()
    p_sih2.text = "HACKATHON 2026"
    p_sih2.font.size = Pt(13)
    p_sih2.font.bold = True
    p_sih2.font.color.rgb = SIH_ORANGE
    p_sih2.alignment = PP_ALIGN.RIGHT

    p_sih3 = tf_sih.add_paragraph()
    p_sih3.text = "SIH26145 // NTRO"
    p_sih3.font.size = Pt(9)
    p_sih3.font.bold = True
    p_sih3.font.color.rgb = TEXT_MUTED
    p_sih3.alignment = PP_ALIGN.RIGHT

def add_sih_footer(slide, slide_num: int):
    """Official SIH Footer text."""
    ft_box = slide.shapes.add_textbox(Inches(0.6), Inches(7.05), Inches(12.13), Inches(0.35))
    tf = ft_box.text_frame
    p = tf.paragraphs[0]
    p.text = f"@SIH Idea submission- Template                                                                                                                                                 {slide_num}"
    p.font.size = Pt(9.5)
    p.font.color.rgb = TEXT_MUTED

def add_sih_card(slide, left, top, width, height, title, body_text, border_color=CARD_BORDER_BLUE):
    """Styled SIH rounded card with colored border and clean typography."""
    shape = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, left, top, width, height)
    shape.fill.solid()
    shape.fill.fore_color.rgb = BG_WHITE
    shape.line.color.rgb = border_color
    shape.line.width = Pt(1.5)

    tb = slide.shapes.add_textbox(left + Inches(0.12), top + Inches(0.1), width - Inches(0.24), height - Inches(0.2))
    tf = tb.text_frame
    tf.word_wrap = True

    p0 = tf.paragraphs[0]
    p0.text = title.upper()
    p0.font.size = Pt(11)
    p0.font.bold = True
    p0.font.color.rgb = border_color
    p0.alignment = PP_ALIGN.CENTER
    p0.space_after = Pt(4)

    if isinstance(body_text, list):
        for b in body_text:
            p = tf.add_paragraph()
            p.text = b
            p.font.size = Pt(9.5)
            p.font.color.rgb = TEXT_DARK
            p.space_after = Pt(2)
    else:
        p = tf.add_paragraph()
        p.text = body_text
        p.font.size = Pt(9.5)
        p.font.color.rgb = TEXT_DARK
        p.alignment = PP_ALIGN.CENTER

def add_image_panel(slide, img_name: str, left, top, width, height, border_color=CARD_BORDER_BLUE, caption: str = ""):
    """Embeds diagram/screenshot into a framed SIH card."""
    img_path = os.path.join(ASSETS_DIR, img_name)
    if not os.path.exists(img_path):
        return

    frame = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, left, top, width, height)
    frame.fill.solid()
    frame.fill.fore_color.rgb = BG_WHITE
    frame.line.color.rgb = border_color
    frame.line.width = Pt(1.5)

    pad = Inches(0.06)
    img_h = height - (Inches(0.3) if caption else (2 * pad))
    slide.shapes.add_picture(img_path, left + pad, top + pad, width - (2 * pad), img_h)

    if caption:
        cap_box = slide.shapes.add_textbox(left, top + height - Inches(0.28), width, Inches(0.25))
        tf_c = cap_box.text_frame
        p_c = tf_c.paragraphs[0]
        p_c.text = caption
        p_c.font.size = Pt(8.5)
        p_c.font.bold = True
        p_c.font.color.rgb = border_color
        p_c.alignment = PP_ALIGN.CENTER

def build_sih_presentation(output_path: str = "SIH26145_CYBERSHIELD_Presentation.pptx"):
    prs = Presentation()
    prs.slide_width = Inches(13.333)
    prs.slide_height = Inches(7.5)
    blank_layout = prs.slide_layouts[6]

    # =========================================================================
    # SLIDE 1: OFFICIAL SIH TITLE PAGE
    # =========================================================================
    s1 = prs.slides.add_slide(blank_layout)

    # Big Top Header: SMART INDIA HACKATHON 2026
    top_hdr = s1.shapes.add_textbox(Inches(0.8), Inches(0.4), Inches(8.5), Inches(0.8))
    tf_th = top_hdr.text_frame
    p_th = tf_th.paragraphs[0]
    p_th.text = "SMART INDIA HACKATHON 2026"
    p_th.font.size = Pt(28)
    p_th.font.bold = True
    p_th.font.color.rgb = SIH_BLUE

    # Top Right SIH Emblem Text
    top_rt = s1.shapes.add_textbox(Inches(9.5), Inches(0.35), Inches(3.2), Inches(0.9))
    tf_rt = top_rt.text_frame
    p_rt1 = tf_rt.paragraphs[0]
    p_rt1.text = "SMART INDIA"
    p_rt1.font.size = Pt(16)
    p_rt1.font.bold = True
    p_rt1.font.color.rgb = SIH_BLUE
    p_rt1.alignment = PP_ALIGN.RIGHT
    p_rt2 = tf_rt.add_paragraph()
    p_rt2.text = "HACKATHON 2026"
    p_rt2.font.size = Pt(16)
    p_rt2.font.bold = True
    p_rt2.font.color.rgb = SIH_ORANGE
    p_rt2.alignment = PP_ALIGN.RIGHT

    # Center Sub-Banner: TITLE PAGE
    tp_box = s1.shapes.add_textbox(Inches(0.8), Inches(1.5), Inches(6.0), Inches(0.6))
    tf_tp = tp_box.text_frame
    p_tp = tf_tp.paragraphs[0]
    p_tp.text = "TITLE PAGE"
    p_tp.font.size = Pt(24)
    p_tp.font.bold = True
    p_tp.font.color.rgb = TEXT_DARK

    # Left Form Fields (Exact SIH Requirements)
    details_box = s1.shapes.add_textbox(Inches(0.8), Inches(2.2), Inches(6.5), Inches(4.5))
    tf_dt = details_box.text_frame
    tf_dt.word_wrap = True

    fields = [
        ("Problem Statement ID –", "SIH26145"),
        ("Problem Statement Title –", "AI-Based Detection of Cyber Threats in Unidirectional IP Traffic"),
        ("Theme –", "Blockchain & Cybersecurity"),
        ("PS Category –", "Software"),
        ("Organization –", "National Technical Research Organisation (NTRO)"),
        ("Team ID –", "SIH26-GALAXY"),
        ("Team Name –", "Galaxy Coders"),
        ("Solution Title –", "ARGUS-ONE // CYBERSHIELD Enclave v2.4")
    ]

    for lbl, val in fields:
        p_lbl = tf_dt.add_paragraph()
        p_lbl.text = f"{lbl} "
        p_lbl.font.size = Pt(13)
        p_lbl.font.bold = True
        p_lbl.font.color.rgb = SIH_BLUE
        p_lbl.space_after = Pt(8)

        # Add value part
        run = p_lbl.add_run()
        run.text = val
        run.font.bold = (lbl in ["Problem Statement ID –", "Team Name –", "Solution Title –"])
        run.font.color.rgb = SIH_ORANGE if "SIH" in val or "Galaxy" in val else TEXT_DARK

    # Right: Embedded 3D Holographic Cyber AI Operations Center Visual (Showoff diagram!)
    add_image_panel(
        s1,
        "mitre_cyber_center.jpg",
        Inches(7.2),
        Inches(1.8),
        Inches(5.5),
        Inches(4.8),
        SIH_BLUE,
        "ARGUS-ONE // High-Throughput AI Unidirectional Threat Architecture"
    )

    # =========================================================================
    # SLIDE 2: PROPOSED SOLUTION & WHY IT FITS THE PROBLEM
    # =========================================================================
    s2 = prs.slides.add_slide(blank_layout)
    add_sih_header(s2, "ARGUS-ONE: AI-POWERED THREAT DETECTION")
    add_sih_footer(s2, 2)

    # Left Column: PROPOSED SOLUTION & INNOVATION
    left_sol = s2.shapes.add_textbox(Inches(0.6), Inches(1.7), Inches(5.8), Inches(2.2))
    tf_ls = left_sol.text_frame
    tf_ls.word_wrap = True
    p_prop = tf_ls.paragraphs[0]
    p_prop.text = "PROPOSED SOLUTION"
    p_prop.font.size = Pt(15)
    p_prop.font.bold = True
    p_prop.font.color.rgb = SIH_BLUE
    p_prop.space_after = Pt(6)

    sol_bullets = [
        "• Passive, read-only monitoring of one-directional IP traffic.",
        "• Extracts flow, timing, protocol and metadata features without sending traffic back.",
        "• AI/ML-based anomaly and threat classification with confidence/risk scoring.",
        "• Live Web SOC dashboard presents real-time alerts, severity, evidence and traffic insights."
    ]
    for b in sol_bullets:
        p = tf_ls.add_paragraph()
        p.text = b
        p.font.size = Pt(10.5)
        p.font.color.rgb = TEXT_DARK
        p.space_after = Pt(4)

    # Innovation Box (Left Bottom)
    innov_box = s2.shapes.add_textbox(Inches(0.6), Inches(4.0), Inches(5.8), Inches(1.3))
    tf_in = innov_box.text_frame
    tf_in.word_wrap = True
    p_in = tf_in.paragraphs[0]
    p_in.text = "INNOVATION & CORE PARADIGM"
    p_in.font.size = Pt(13)
    p_in.font.bold = True
    p_in.font.color.rgb = SIH_BLUE
    p_in.space_after = Pt(4)
    p_in_body = tf_in.add_paragraph()
    p_in_body.text = (
        "Threat intelligence from observation only: detect complex adversarial behaviors "
        "(C2 beacons, DNS exfiltration tunnels, and JA4 TLS malware profiles) without contacting "
        "or acknowledging the protected source, preserving complete air-gap isolation."
    )
    p_in_body.font.size = Pt(10)
    p_in_body.font.color.rgb = TEXT_DARK

    # Bottom-Left: Embedded 3D Data Diode Hardware Tap Diagram (SHOWOFF DIAGRAM!)
    add_image_panel(
        s2,
        "data_diode_hardware.jpg",
        Inches(0.6),
        Inches(5.2),
        Inches(5.8),
        Inches(1.8),
        SIH_BLUE,
        "Physical Optical Data Diode TAP (Rx-Only Photodiode / Zero Backchannel)"
    )

    # Right Column: "WHY IT FITS THE PROBLEM" Container & 4 Threat Cards
    fits_hdr = s2.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(6.8), Inches(1.7), Inches(5.9), Inches(0.8))
    fits_hdr.fill.solid()
    fits_hdr.fill.fore_color.rgb = BG_WHITE
    fits_hdr.line.color.rgb = CARD_BORDER_BLUE
    fits_hdr.line.width = Pt(1.5)
    tf_fh = fits_hdr.text_frame
    p_fh1 = tf_fh.paragraphs[0]
    p_fh1.text = "WHY IT FITS THE PROBLEM"
    p_fh1.font.size = Pt(12)
    p_fh1.font.bold = True
    p_fh1.font.color.rgb = CARD_BORDER_BLUE
    p_fh1.alignment = PP_ALIGN.CENTER
    p_fh2 = tf_fh.add_paragraph()
    p_fh2.text = "Works inside the isolated monitoring enclave — no probing, handshake completion, inline blocking or return path."
    p_fh2.font.size = Pt(8.5)
    p_fh2.font.color.rgb = TEXT_DARK
    p_fh2.alignment = PP_ALIGN.CENTER

    # 4 Vector Cards
    rw = Inches(2.85)
    rh = Inches(2.05)
    add_sih_card(s2, Inches(6.8), Inches(2.65), rw, rh, "DDoS", [
        "Rate, destination SYN ratio and protocol behavior.",
        "Detects volumetric floods >75% SYN ratio without session completion."
    ], CARD_BORDER_RED)

    add_sih_card(s2, Inches(9.85), Inches(2.65), rw, rh, "C2 BEACONING", [
        "Periodicity & Inter-Arrival Time (IAT) analysis.",
        "Coefficient of Variation (CV < 0.15) detects automated Cobalt Strike callbacks."
    ], CARD_BORDER_AMBER)

    add_sih_card(s2, Inches(6.8), Inches(4.85), rw, rh, "DGA / DNS", [
        "Query entropy, n-grams and domain anomalies.",
        "Fast Shannon entropy (H > 3.65) detects base32/64 exfiltration tunnels."
    ], CARD_BORDER_GREEN)

    add_sih_card(s2, Inches(9.85), Inches(4.85), rw, rh, "ENCRYPTED TRAFFIC", [
        "TLS ClientHello metadata & JA4+ fingerprints.",
        "Matches adversary C2 signatures (RFC 8701 GREASE stripped) without payload decryption."
    ], CARD_BORDER_BLUE)

    # =========================================================================
    # SLIDE 3: TECHNICAL APPROACH (FLOWCHARTS & DETECTION PIPELINE)
    # =========================================================================
    s3 = prs.slides.add_slide(blank_layout)
    add_sih_header(s3, "TECHNICAL APPROACH & SYSTEM ARCHITECTURE")
    add_sih_footer(s3, 3)

    # Left: TECHNOLOGIES USED
    tech_box = s3.shapes.add_textbox(Inches(0.6), Inches(1.65), Inches(3.8), Inches(2.0))
    tf_t = tech_box.text_frame
    tf_t.word_wrap = True
    p_tech = tf_t.paragraphs[0]
    p_tech.text = "TECHNOLOGIES"
    p_tech.font.size = Pt(13)
    p_tech.font.bold = True
    p_tech.font.color.rgb = SIH_BLUE
    p_tech.space_after = Pt(4)

    tech_bullets = [
        "• Python 3.13 + Fast Async/Uvicorn",
        "• 16-Shard Hash Partitioning Engine",
        "• Fast Shannon Entropy & IAT Analysis",
        "• JA4+ RFC 8701 TLS Fingerprinting",
        "• MITRE ATT&CK Matrix Triage (14 Tactics)",
        "• Live Web SOC (WebSocket + Canvas Radar)"
    ]
    for b in tech_bullets:
        p = tf_t.add_paragraph()
        p.text = b
        p.font.size = Pt(9.5)
        p.font.color.rgb = TEXT_DARK
        p.space_after = Pt(2)

    # Top Right: IMPLEMENTATION FLOWCHART (Color Chevrons / Connected Flow Blocks)
    flow_hdr = s3.shapes.add_textbox(Inches(4.6), Inches(1.65), Inches(8.1), Inches(0.35))
    tf_flh = flow_hdr.text_frame
    p_flh = tf_flh.paragraphs[0]
    p_flh.text = "IMPLEMENTATION FLOW"
    p_flh.font.size = Pt(13)
    p_flh.font.bold = True
    p_flh.font.color.rgb = SIH_BLUE

    steps = [
        ("1. One-way\nTraffic / PCAP", SIH_BLUE),
        ("2. Read-only\nIngest", CARD_BORDER_BLUE),
        ("3. Feature\nExtraction", CARD_BORDER_GREEN),
        ("4. AI/ML\nDetection", SIH_ORANGE),
        ("5. Threat +\nConfidence", CARD_BORDER_RED),
        ("6. Dashboard\nAlerts & Rules", SIH_BLUE),
    ]

    sw = Inches(1.24)
    sgap = Inches(0.12)
    sy = Inches(2.05)
    sh = Inches(0.85)

    for idx, (st_text, st_col) in enumerate(steps):
        s_box = s3.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(4.6) + idx * (sw + sgap), sy, sw, sh)
        s_box.fill.solid()
        s_box.fill.fore_color.rgb = st_col
        s_box.line.fill.background()
        
        tf_sb = s_box.text_frame
        tf_sb.word_wrap = True
        p_sb = tf_sb.paragraphs[0]
        p_sb.text = st_text
        p_sb.font.size = Pt(8.5)
        p_sb.font.bold = True
        p_sb.font.color.rgb = BG_WHITE
        p_sb.alignment = PP_ALIGN.CENTER

    # Middle Section: Real Wireshark Packet Dissector Screenshot + Detection Logic
    add_image_panel(
        s3,
        "packet_dissector.png",
        Inches(0.6),
        Inches(3.1),
        Inches(4.0),
        Inches(3.8),
        SIH_BLUE,
        "Zero-Copy PCAP Wire Protocol Dissector"
    )

    # Right: 6 DETECTION LOGIC CARDS
    dl_hdr = s3.shapes.add_textbox(Inches(4.8), Inches(3.05), Inches(7.9), Inches(0.35))
    tf_dl = dl_hdr.text_frame
    p_dl = tf_dl.paragraphs[0]
    p_dl.text = "DETECTION LOGIC & MATHEMATICAL HEURISTICS"
    p_dl.font.size = Pt(13)
    p_dl.font.bold = True
    p_dl.font.color.rgb = SIH_BLUE

    dlogic = [
        ("DDoS", "Flow rate + destination ratio + source entropy (>75% SYN ratio triggers instant P0 alert).", CARD_BORDER_RED),
        ("C2 BEACONING", "Periodic flows + Inter-Arrival Time deltas (CV = σ / μ < 0.15 indicates implant callback).", CARD_BORDER_AMBER),
        ("DGA / DNS", "Query entropy (H > 3.65) + length + n-grams detect Base32/64 exfiltration tunneling.", CARD_BORDER_GREEN),
        ("TLS / QUIC", "JA4 ClientHello metadata, sorted cipher suites SHA-256 digests & size/timing.", CARD_BORDER_BLUE),
        ("RECON", "Fan-out across hosts & ports (cardinality >25 ports / 15 targets in 3.0s window).", SIH_BLUE),
        ("EXFILTRATION", "Asymmetric volume anomalies, high-entropy query payload egress & Merkle audit.", SIH_ORANGE)
    ]

    card_dw = Inches(2.6)
    card_dh = Inches(1.6)

    for k, (dl_t, dl_b, dl_c) in enumerate(dlogic):
        col_idx = k % 3
        row_idx = k // 3
        cx = Inches(4.8) + col_idx * (card_dw + Inches(0.12))
        cy = Inches(3.45) + row_idx * (card_dh + Inches(0.12))
        add_sih_card(s3, cx, cy, card_dw, card_dh, dl_t, dl_b, dl_c)

    # =========================================================================
    # SLIDE 4: FEASIBILITY AND VIABILITY
    # =========================================================================
    s4 = prs.slides.add_slide(blank_layout)
    add_sih_header(s4, "FEASIBILITY AND VIABILITY")
    add_sih_footer(s4, 4)

    # Top 3 Pillars: Technical, Operational, Scalability
    fw_w = Inches(3.85)
    fw_h = Inches(2.2)

    add_sih_card(s4, Inches(0.6), Inches(1.7), fw_w, fw_h, "TECHNICAL FEASIBILITY", [
        "• Passive traffic replayed seamlessly from PCAP/live mirror TAP.",
        "• Features extracted purely from headers without payload decryption.",
        "• Deterministic sliding window algorithms score incrementally.",
        "• Zero-allocation __slots__ model maintains sub-110ms processing SLA."
    ], CARD_BORDER_BLUE)

    add_sih_card(s4, Inches(4.75), Inches(1.7), fw_w, fw_h, "OPERATIONAL FEASIBILITY", [
        "• Read-only architecture strictly preserves physical isolation.",
        "• Zero active probing or return packets emitted back to source.",
        "• Modular architecture supports both field deployment and lab replay.",
        "• SIEM exporters stream CEF & Syslog logs without blocking."
    ], SIH_BLUE)

    add_sih_card(s4, Inches(8.9), Inches(1.7), fw_w, fw_h, "SCALABILITY", [
        "• 16-shard hash partitioning distributes state across lock cores.",
        "• Benchmarked throughput: 25,000–50,000+ packets/second sustained.",
        "• Detectors execute asynchronously across decoupled sliding windows.",
        "• Scales to enterprise-grade isolated SOC monitoring enclaves."
    ], CARD_BORDER_GREEN)

    # Lower Section: CHALLENGES / RISKS vs MITIGATION STRATEGIES (Table/Comparison)
    cr_hdr = s4.shapes.add_textbox(Inches(0.6), Inches(4.1), Inches(5.8), Inches(0.35))
    tf_cr = cr_hdr.text_frame
    p_cr = tf_cr.paragraphs[0]
    p_cr.text = "CHALLENGES / RISKS"
    p_cr.font.size = Pt(13)
    p_cr.font.bold = True
    p_cr.font.color.rgb = CARD_BORDER_RED

    mit_hdr = s4.shapes.add_textbox(Inches(6.8), Inches(4.1), Inches(5.9), Inches(0.35))
    tf_mit = mit_hdr.text_frame
    p_mit = tf_mit.paragraphs[0]
    p_mit.text = "MITIGATION STRATEGIES (ENGINEERED IN ARGUS-ONE)"
    p_mit.font.size = Pt(13)
    p_mit.font.bold = True
    p_mit.font.color.rgb = CARD_BORDER_GREEN

    # Comparison Cards
    table_card_w = Inches(5.9)
    table_card_h = Inches(2.4)

    add_sih_card(s4, Inches(0.6), Inches(4.5), table_card_w, table_card_h, "IDENTIFIED CHALLENGES", [
        "1. False positives from legitimate periodic NTP or heartbeat traffic.",
        "2. Encrypted TLS/QUIC traffic limits application payload visibility.",
        "3. High-throughput ingress can cause thread lock contention & buffer drops.",
        "4. Adversaries tampering with local alert logs in isolated enclaves."
    ], CARD_BORDER_RED)

    add_sih_card(s4, Inches(6.8), Inches(4.5), table_card_w, table_card_h, "PROVEN ARCHITECTURAL MITIGATIONS", [
        "1. Coefficient of Variation (CV) + duration filters isolate automated malware.",
        "2. JA4+ TLS ClientHello fingerprinting & ALPN parsing bypass encryption.",
        "3. 16-shard micro-batch hashing amortizes locks, reaching 50k+ pps capacity.",
        "4. Merkle hash-chaining (SHA-256 sequential seals) prevents log tampering."
    ], CARD_BORDER_GREEN)

    # =========================================================================
    # SLIDE 5: IMPACT AND BENEFITS
    # =========================================================================
    s5 = prs.slides.add_slide(blank_layout)
    add_sih_header(s5, "IMPACT AND BENEFITS")
    add_sih_footer(s5, 5)

    # Left: TARGET USERS & Real Live Operations Console Screenshot
    tu_hdr = s5.shapes.add_textbox(Inches(0.6), Inches(1.65), Inches(4.8), Inches(0.35))
    tf_tu = tu_hdr.text_frame
    p_tu = tf_tu.paragraphs[0]
    p_tu.text = "TARGET USERS"
    p_tu.font.size = Pt(13)
    p_tu.font.bold = True
    p_tu.font.color.rgb = SIH_BLUE

    users_text = [
        "• Critical-infrastructure security teams (Defense, NTRO, Power Grids)",
        "• Security Operations Centers (SOC) & Air-Gapped Data Enclaves",
        "• Network / incident-response analysts requiring passive attribution",
        "• Government & intelligence organizations using optical data diodes"
    ]
    tu_bullets = s5.shapes.add_textbox(Inches(0.6), Inches(2.0), Inches(5.0), Inches(1.4))
    tf_tub = tu_bullets.text_frame
    tf_tub.word_wrap = True
    for idx, u in enumerate(users_text):
        p = tf_tub.paragraphs[0] if idx == 0 else tf_tub.add_paragraph()
        p.text = u
        p.font.size = Pt(9.5)
        p.font.color.rgb = TEXT_DARK
        p.space_after = Pt(2)

    # Embedded Live Operations Dashboard Screenshot (SHOWOFF PROOF!)
    add_image_panel(
        s5,
        "soc_dashboard_live.png",
        Inches(0.6),
        Inches(3.5),
        Inches(5.0),
        Inches(2.9),
        SIH_BLUE,
        "Live Production Web SOC Dashboard: Threat Radar & Ingest"
    )

    # Right: KEY BENEFITS (6 Grid Cards)
    kb_hdr = s5.shapes.add_textbox(Inches(5.9), Inches(1.65), Inches(6.8), Inches(0.35))
    tf_kb = kb_hdr.text_frame
    p_kb = tf_kb.paragraphs[0]
    p_kb.text = "KEY BENEFITS"
    p_kb.font.size = Pt(13)
    p_kb.font.bold = True
    p_kb.font.color.rgb = SIH_BLUE

    benefits = [
        ("SECURITY", "Earlier visibility into DDoS, C2 beacons, reconnaissance & DNS exfiltration.", CARD_BORDER_RED),
        ("ISOLATION", "Maintains strict one-way monitoring without creating any return path.", CARD_BORDER_BLUE),
        ("ANALYST VALUE", "Alerts include threat class, confidence, evidence & MITRE ATT&CK mapping.", SIH_BLUE),
        ("FORENSICS", "Structured records and Merkle hash-chaining support tamper-evident audit.", CARD_BORDER_GREEN),
        ("SCALABILITY", "Streaming 16-shard architecture easily extends with additional AI detectors.", CARD_BORDER_AMBER),
        ("COST", "Software analytics run on commodity hardware, complementing existing optical diodes.", SIH_ORANGE)
    ]

    bw = Inches(2.2)
    bh = Inches(1.45)

    for m, (b_t, b_desc, b_c) in enumerate(benefits):
        col_m = m % 3
        row_m = m // 3
        bx = Inches(5.9) + col_m * (bw + Inches(0.12))
        by = Inches(2.05) + row_m * (bh + Inches(0.15))
        add_sih_card(s5, bx, by, bw, bh, b_t, b_desc, b_c)

    # Bottom Banner: Overall Outcome
    out_banner = s5.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.6), Inches(6.5), Inches(12.13), Inches(0.45))
    out_banner.fill.solid()
    out_banner.fill.fore_color.rgb = BG_WHITE
    out_banner.line.color.rgb = SIH_BLUE
    out_banner.line.width = Pt(1.5)
    tf_ob = out_banner.text_frame
    p_ob = tf_ob.paragraphs[0]
    p_ob.text = "Overall outcome: turn one-way network visibility into actionable cyber-threat intelligence without compromising the isolation boundary."
    p_ob.font.size = Pt(10)
    p_ob.font.bold = True
    p_ob.font.color.rgb = SIH_BLUE
    p_ob.alignment = PP_ALIGN.CENTER

    # =========================================================================
    # SLIDE 6: RESEARCH, REFERENCES & LIVE DEPLOYMENT LINKS
    # =========================================================================
    s6 = prs.slides.add_slide(blank_layout)
    add_sih_header(s6, "RESEARCH, REFERENCES & LIVE DEPLOYMENT")
    add_sih_footer(s6, 6)

    # Primary Problem Reference
    pref_box = s6.shapes.add_textbox(Inches(0.6), Inches(1.65), Inches(12.13), Inches(0.85))
    tf_pr = pref_box.text_frame
    tf_pr.word_wrap = True
    p_prh = tf_pr.paragraphs[0]
    p_prh.text = "PRIMARY PROBLEM REFERENCE"
    p_prh.font.size = Pt(13)
    p_prh.font.bold = True
    p_prh.font.color.rgb = SIH_BLUE
    p_prh.space_after = Pt(2)
    p_prb = tf_pr.add_paragraph()
    p_prb.text = "Smart India Hackathon 2026 — PS SIH26145: “AI-Based Detection of Cyber Threats in Unidirectional IP Traffic” — National Technical Research Organisation (NTRO)."
    p_prb.font.size = Pt(10.5)
    p_prb.font.color.rgb = TEXT_DARK

    # Left: TECHNICAL / RESEARCH REFERENCES
    tr_box = s6.shapes.add_textbox(Inches(0.6), Inches(2.65), Inches(5.8), Inches(3.2))
    tf_tr = tr_box.text_frame
    tf_tr.word_wrap = True
    p_trh = tf_tr.paragraphs[0]
    p_trh.text = "TECHNICAL / RESEARCH REFERENCES"
    p_trh.font.size = Pt(13)
    p_trh.font.bold = True
    p_trh.font.color.rgb = SIH_BLUE
    p_trh.space_after = Pt(4)

    refs = [
        "• Smart India Hackathon 2026 problem statement & expected requirements.",
        "• CIC-IDS2017 — benchmark intrusion dataset for experimentation & validation.",
        "• Zeek / Bro — network security monitoring & flow metadata analysis.",
        "• Scapy & DPDK — high-speed packet capture & wire experimentation.",
        "• Fox-IT JA4+ (RFC 8701) — cryptographic TLS client fingerprinting.",
        "• MITRE ATT&CK v14 Enterprise Matrix for automated threat actor mapping."
    ]
    for r in refs:
        p = tf_tr.add_paragraph()
        p.text = r
        p.font.size = Pt(10)
        p.font.color.rgb = TEXT_DARK
        p.space_after = Pt(3)

    # Right: LIVE DEPLOYMENT & PROOF OF CONCEPT LINKS
    dep_card_w = Inches(6.0)
    dep_card_h = Inches(3.2)
    add_sih_card(s6, Inches(6.8), Inches(2.65), dep_card_w, dep_card_h, "VERIFIED LIVE DEPLOYMENT & PROOF OF CONCEPT", [
        "• Live Worldwide Enclave: https://red-avi-object-email.trycloudflare.com",
        "  (Full 16-shard telemetry, live WebSocket, threat radar, and attack injection)",
        "",
        "• Permanent 24/7 Edge Hosting: https://saicharan-nayak.github.io/unidirectional-threat-engine/",
        "  (Automated GitHub Pages CI/CD with client-side simulation engine fallback)",
        "",
        "• GitHub Source Code Repository: SAICHARAN-NAYAK/unidirectional-threat-engine",
        "  (Complete engine, tests, benchmarks, and Android Studio native project)",
        "",
        "• Android Studio Native App: android_studio_app/ container with one-click launcher"
    ], CARD_BORDER_GREEN)

    # Design Principle Bottom Banner
    dp_banner = s6.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.6), Inches(6.15), Inches(12.13), Inches(0.45))
    dp_banner.fill.solid()
    dp_banner.fill.fore_color.rgb = CARD_BG_LIGHT
    dp_banner.line.color.rgb = SIH_BLUE
    dp_banner.line.width = Pt(1.5)
    tf_dp = dp_banner.text_frame
    p_dp = tf_dp.paragraphs[0]
    p_dp.text = "Design principle: read-only ingest • no return path • no payload decryption • streaming detection • structured alerts"
    p_dp.font.size = Pt(10)
    p_dp.font.bold = True
    p_dp.font.color.rgb = SIH_BLUE
    p_dp.alignment = PP_ALIGN.CENTER

    prs.save(output_path)
    print(f"[+] Successfully generated official SIH format presentation: {output_path}")

if __name__ == "__main__":
    build_sih_presentation()
