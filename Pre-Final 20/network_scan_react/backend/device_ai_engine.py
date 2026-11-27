from datetime import datetime


def analyze_device(device):

    score = device.get("deviceRiskScore", 0)
    reasons = [
        reason.get("text", "")
        for reason in device.get("deviceRiskReasons", [])
    ]
    recommendations = [
        {
            "icon": reason.get("icon", "💡"),
            "text": reason.get("recommendation", "")
        }
        for reason in device.get("deviceRiskReasons", [])
        if reason.get("recommendation")
    ]

    # Attack Surface
    attack_surface = []

    if device.get("httpBannerDetected"):
        attack_surface.append("🌐 HTTP")

    if device.get("httpScheme") == "HTTPS":
        attack_surface.append("🔒 HTTPS")

    if device.get("snmpEnabled"):
        attack_surface.append("📡 SNMP")

    if device.get("sshBannerDetected"):
        attack_surface.append("🔑 SSH")

    open_ports = str(device.get("openPorts", "")).upper()

    ports = {
        port.strip()
        for port in str(device.get("openPorts", "")).split(",")
        if port.strip()
    }

    if "21" in ports:
        attack_surface.append("📁 FTP")

    if "23" in ports:
        attack_surface.append("⚠️ Telnet")

    if "1900" in open_ports or "UPNP" in str(device.get("discoverySource", "")).upper():
        attack_surface.append("📺 UPnP")

    # Risk Score
    risk = device.get("deviceRiskLevel", "Low")

    # Discovery Protocols
    discovery = device.get("discoverySource", "")

    if discovery:
        reasons.append(
            f"Device discovered using {discovery}."
        )


    # Default Message
    if not reasons:
        reasons.append(
            "No significant security findings detected."
        )

    if not recommendations:
        recommendations.append(
            "Continue periodic security monitoring."
        )


    # Final Result

    hostname = device.get("hostname") or device.get("ip") or "Unknown Device"

    top_findings = ", ".join(reasons[:3])

    if top_findings:
        summary = (
            f"{hostname} is classified as a {risk} risk device "
            f"(Score: {score}/100). "
            f"Primary findings: {top_findings}."
        )
    else:
        summary = (
            f"{hostname} is classified as a {risk} risk device "
            f"(Score: {score}/100). "
            f"No significant security findings were detected."
        )

    confidence = min(
        95,
        70 + len(reasons) * 5
    )

    # Device Security Grade
    if score >= 80:
        security_grade = "F"
    elif score >= 60:
        security_grade = "C"
    elif score >= 40:
        security_grade = "B"
    elif score >= 20:
        security_grade = "A"
    else:
        security_grade = "A+"

    now = datetime.now()

    analysis_time = now.strftime("%H:%M:%S")

    analysis_date = now.strftime("%d-%b-%Y %H:%M:%S")

    # Executive Security Summary
    if score >= 80:
        executive_summary = (
            "Immediate action required. This device has multiple high-risk "
            "security findings and should be reviewed without delay."
        )
    elif score >= 60:
        executive_summary = (
            "High-risk configuration detected. Review exposed services and "
            "strengthen device security."
        )
    elif score >= 40:
        executive_summary = (
            "Moderate security posture. Some improvements are recommended."
        )
    else:
        executive_summary = (
            "Good security posture. Continue routine monitoring and maintenance."
        )


    # AI Risk Indicators
    risk_indicators = []

    if device.get("httpBannerDetected"):
        risk_indicators.append("🌐 HTTP Interface")

    if device.get("snmpEnabled"):
        risk_indicators.append("📡 SNMP Enabled")

    if device.get("sshBannerDetected"):
        risk_indicators.append("🔑 SSH Enabled")

    if "UPNP" in str(device.get("discoverySource", "")).upper():
        risk_indicators.append("📺 UPnP Available")

    if not device.get("operatingSystem"):
        risk_indicators.append("⚠️ Unknown Operating System")

    # Security Posture
    if score >= 80:
        security_posture = "🔴 Critical - Immediate remediation required."
    elif score >= 60:
        security_posture = "🟠 High - Review exposed services and harden the device."
    elif score >= 40:
        security_posture = "🟡 Moderate - Improve security configuration."
    else:
        security_posture = "🟢 Healthy - Continue routine monitoring."

    # AI Device Fingerprinting
    fingerprint = "Unknown Network Device"

    if device.get("category", "").lower() == "gateway":
        fingerprint = "Internet Gateway"

    elif "router" in str(device.get("deviceType", "")).lower():
        fingerprint = "Residential WiFi Router"

    elif "switch" in str(device.get("deviceType", "")).lower():
        fingerprint = "Managed Ethernet Switch"

    elif "access point" in str(device.get("deviceType", "")).lower():
        fingerprint = "Wireless Access Point"

    elif "printer" in str(device.get("deviceType", "")).lower():
        fingerprint = "Network Printer"

    elif "camera" in str(device.get("deviceType", "")).lower():
        fingerprint = "IP Surveillance Camera"

    elif "android" in str(device.get("operatingSystem", "")).lower():
        fingerprint = "Android Smart Device"

    elif "windows" in str(device.get("operatingSystem", "")).lower():
        fingerprint = "Windows Computer"

    return {

        "ai": summary,

        "executiveSummary": executive_summary,

        "aiModel": "Rule-Based AI Engine",

        "deviceType": device.get("deviceType", "-"),

        "fingerprint": fingerprint,

        "category": device.get("category", "-"),

        "riskScore": score,

        "riskLevel": risk,

        "riskCategory": "Network Device Security",

        "securityGrade": security_grade,

        "attackSurface": attack_surface,

        "riskIndicators": risk_indicators,

        "securityPosture": security_posture,

        "confidence": confidence,

        "analysisTime": analysis_time,

        "analyzedAt": analysis_date,

        "operatingSystem": device.get("operatingSystem", "-"),

        "manufacturer": device.get("manufacturer", "-"),

        "model": device.get("model", "-"),

        "ip": device.get("ip", ""),

        "mac": device.get("mac", ""),

        "reasons": reasons,

        "recommendations": recommendations
    }