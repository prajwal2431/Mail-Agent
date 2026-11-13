#!/usr/bin/env python3
"""Read Gmail, label old junk for review, and show the result on a local page.

Open the page with: python mail_agent.py --serve
It writes mail_out/mail.html and mail_out/mail_index.csv. Nothing is trashed or deleted.
Old promotions and old notifications get the Gmail label Agent/MarkDelete.
A mail with a document attached (PDF, Word, Excel, and the like) gets
Agent/Attachment and is never marked for delete. Nothing is trashed or deleted.

Important mail is decided from the subject, sender, and snippet. Money, tax,
documents, security alerts, interviews, and events are never labeled for delete.
A promotion is labeled only after it is older than three calendar months.
Younger promotions are summarized and left alone.

First run: save an OAuth desktop client as credentials.json beside this file,
then: python mail_agent.py --limit 100
"""

from __future__ import annotations

import argparse
import calendar
import csv
import datetime
import email.header
import email.utils
import html
import os
import re
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import webbrowser
from collections import Counter, defaultdict
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

SCOPES = ["https://www.googleapis.com/auth/gmail.modify"]
QUERY = "-in:spam -in:trash -in:sent -in:drafts -in:chats"
PAGE_PORT = 8765
SCAN_LOCK = threading.Lock()
MARK_LABEL = "Agent/MarkDelete"
ATTACH_LABEL = "Agent/Attachment"
DOC_SUFFIXES = (
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".csv", ".txt", ".rtf", ".odt", ".ods", ".odp", ".zip", ".rar", ".7z",
)
DOC_MIMES = {
    "application/pdf",
    "application/msword",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.ms-excel",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.ms-powerpoint",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "text/csv",
    "application/zip",
    "application/x-zip-compressed",
}
# ponytail: four MIME levels, no message body. A document nested deeper is missed.
# Upgrade path: walk payload.parts with no depth cap.
_PART_FIELDS = "mimeType,filename,body(attachmentId)"
MESSAGE_FIELDS = (
    "id,internalDate,labelIds,snippet,"
    "payload(mimeType,filename,headers(name,value),body(attachmentId),"
    f"parts({_PART_FIELDS},parts({_PART_FIELDS},parts({_PART_FIELDS},parts({_PART_FIELDS})))))"
)
FETCH_BATCH = 40
# Published Gmail costs. messages.get is 60 because the download uses format=full.
# https://developers.google.com/workspace/gmail/api/reference/quota
DAILY_QUOTA = 80_000_000
MINUTE_QUOTA = 6_000
METHOD_UNITS = {
    "messages.list": 5,
    "messages.get": 60,
    "messages.batchModify": 50,
    "labels.list": 1,
    "labels.create": 5,
}
AUDIT_FIELDS = (
    "ran_at",
    "messages_list",
    "messages_get",
    "messages_batch_modify",
    "labels_list",
    "labels_create",
    "units",
    "peak_minute",
    "today_units",
    "alert",
)
HERE = Path(__file__).resolve().parent
MONTHS = "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split()

# gmail.modify is the scope that can add a label. This script never calls
# delete, trash, or send.

MONEY_RE = re.compile(
    r"("
    r"\b(credited|debited)\b|"
    r"\bavailable balance\b|"
    r"\b(upi|imps|neft|rtgs|nach)\b|"
    r"\b(e-?statement|account statement|bank statement|mini statement|credit card statement|monthly statement|statement of account|consolidated statement)\b|"
    r"\bpayment (received|successful|failed|due)\b|"
    r"\bamount (paid|debited|credited)\b|"
    r"\btransaction (alert|successful|failed)\b|"
    r"\b(a/c|account)\s*(no\.?|number|ending|xx)\b|"
    r"\b(payslip|salary credited)\b"
    r")",
    re.I,
)
STRONG_DOC_RE = re.compile(
    r"\b("
    r"form[\s-]?16|income tax|\bitr\b|gst return|aadhaar|aadhar|e-?pan|pan card|"
    r"marksheet|grade card|hall ticket|admit card|experience letter|relieving letter|"
    r"legal notice|e-?challan|lab report|prescription|discharge summary|"
    r"insurance policy|policy document|premium due|dependabot|security advisory|"
    r"invoice|payment receipt|order confirmed|order confirmation"
    r")\b",
    re.I,
)
WEAK_DOC_RE = re.compile(
    r"\b(passport|itinerary|boarding pass|e-ticket|booking confirmed)\b",
    re.I,
)
SECURITY_RE = re.compile(
    r"("
    r"\bpassword (has been |was )?(changed|reset|updated)\b|"
    r"\bnew (sign-?in|login|device)\b|"
    r"\bsuspicious (sign-?in|login|activity)\b|"
    r"\bsecurity alert\b"
    r")",
    re.I,
)
OTP_RE = re.compile(
    r"("
    r"\bone[- ]time password\b|"
    r"\bone[- ]time pin\b|"
    r"\botp\b|"
    r"\b\d{4,8}\b is your\b.{0,24}\b(code|otp)\b|"
    r"\byour (verification|login) code\b"
    r")",
    re.I,
)
REJECTION_RE = re.compile(
    r"\b("
    r"regret to inform|not be moving forward|not moving forward|other candidates|"
    r"unsuccessful|not selected|not shortlisted|will not be proceeding|"
    r"decided not to (move|proceed)|position has been filled|unable to (move forward|offer)"
    r")\b",
    re.I,
)
OFFER_RE = re.compile(
    r"\b(pleased to offer|offer of employment|your offer letter|appointment letter|enclosed offer|offer letter)\b",
    re.I,
)
SELECTION_RE = re.compile(
    r"("
    r"\b(you have been|you've been|you are) (shortlisted|selected)\b|"
    r"\b(shortlisted|selected) for (the )?(role|position|interview|next round)\b|"
    r"\bcongratulations\b.{0,40}\b(selected|shortlisted|offer)\b"
    r")",
    re.I,
)
CALL_RE = re.compile(
    r"("
    r"\b(interview|phone screen|hr round|technical round)\b.{0,40}\b(scheduled|confirmed|rescheduled)\b|"
    r"\binvit(?:e|ed|ation) to (an |the )?interview\b|"
    r"\binterview invitation\b|"
    r"\byour (coding test|online assessment)\b|"
    r"\b(coding test|online assessment)\b.{0,30}\b(scheduled|link|invite)\b"
    r")",
    re.I,
)
APPLICATION_RE = re.compile(
    r"\b(your application|your candidature|application status|application update|update on your application)\b",
    re.I,
)
APPLIED_RE = re.compile(
    r"("
    r"\byour application (was|has been|is) (sent|submitted|received)\b|"
    r"\bapplication (sent|submitted|received)\b|"
    r"\bthank(s| you) for (applying|your application)\b|"
    r"\bwe('ve| have)? received your application\b|"
    r"\byou (have )?(successfully )?applied (for|to)\b|"
    r"\bsuccessfully applied\b|"
    r"\bapplication confirmation\b|"
    r"\bindeed application:"
    r")",
    re.I,
)
UNFORTUNATELY_RE = re.compile(r"\bunfortunately\b", re.I)
CANDIDATE_RE = re.compile(r"\b(your candidacy|your profile|interest in (the |this |our )?(role|position|opportunity))\b", re.I)
GHOST_DAYS = 30
COMPANY_AT_RE = re.compile(r"\bat\s+([A-Z][\w&.'\- ]+)")
COMPANY_PHRASE_RE = re.compile(
    r"\b(?:application (?:was |has been )?sent to|applied to|applying to|application to|application with|"
    r"application at|interest in|candidature at|journey with)\s+(.+)",
    re.I,
)
COMPANY_END_RE = re.compile(
    r"[!?,|:;()\[\]]|\s[-\u2013\u2014]\s|\.\s|\.$|\s(?:for|as|on|in|via|and|we|has|is|was|team)\s", re.I
)
COMPANY_NOISE = {
    "careers", "career", "recruiting", "recruitment", "recruiter", "talent", "acquisition", "hiring", "hr",
    "team", "jobs", "job", "noreply", "no-reply", "notifications", "the", "via", "people", "india",
}
COMPANY_SUFFIX = {
    "pvt", "private", "ltd", "limited", "inc", "llc", "llp", "corp", "corporation", "co", "company",
    "technologies", "technology", "tech", "labs", "solutions", "software", "services", "systems",
    "india", "global", "group", "the",
}
FREE_MAIL = {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "live.com", "icloud.com", "rediffmail.com"}
OUTCOMES = (
    ("rejection", "Rejected"),
    ("selection", "Selected"),
    ("offer", "Offer"),
    ("call", "Interview call"),
    ("ghosted", "Ghosted"),
    ("waiting", "Waiting"),
)
OUTCOME_RANK = {"call": 1, "rejection": 2, "selection": 3, "offer": 4}
# ponytail: platform comes from the sender domain. A rejection sent by the company's own
# address counts under "Company or other", not the job board you applied on.
PLATFORMS = (
    ("linkedin.com", "LinkedIn"),
    ("naukri.com", "Naukri"),
    ("indeed.com", "Indeed"),
    ("internshala.com", "Internshala"),
    ("unstop.com", "Unstop"),
    ("wellfound.com", "Wellfound"),
    ("angel.co", "Wellfound"),
    ("instahyre.com", "Instahyre"),
    ("foundit.in", "Foundit"),
    ("monsterindia.com", "Foundit"),
    ("glassdoor.com", "Glassdoor"),
    ("glassdoor.co.in", "Glassdoor"),
    ("cutshort.io", "Cutshort"),
    ("hirist.tech", "Hirist"),
    ("iimjobs.com", "iimjobs"),
    ("apna.co", "Apna"),
    ("myworkday.com", "Company portal"),
    ("myworkdayjobs.com", "Company portal"),
    ("greenhouse.io", "Company portal"),
    ("greenhouse-mail.io", "Company portal"),
    ("lever.co", "Company portal"),
    ("ashbyhq.com", "Company portal"),
    ("smartrecruiters.com", "Company portal"),
    ("icims.com", "Company portal"),
    ("successfactors.com", "Company portal"),
    ("zohorecruit.com", "Company portal"),
    ("darwinbox.in", "Company portal"),
)
JOB_STAGES = (
    ("applied", "Applied"),
    ("call", "Interview call"),
    ("selection", "Selected"),
    ("offer", "Offer"),
    ("rejection", "Rejected"),
    ("career", "Update"),
)
ADVICE_RE = re.compile(
    r"\b(how to|tips|guide|template|webinar|workshop|crack (the )?interview|resume)\b",
    re.I,
)
EVENT_RE = re.compile(
    r"("
    r"\b(hackathon|hackfest|hack day|devfolio|unstop|dare2compete|webinar|workshop|meetup|seminar)\b|"
    r"\bregistration (closes|ends|deadline|open)\b"
    r")",
    re.I,
)
PROMO_RE = re.compile(
    r"("
    r"\b\d+\s?%\s?off\b|"
    r"\b(discount|coupon|voucher|cashback|newsletter|unsubscribe|shop now|flash sale|limited[- ]time|special offer|exclusive offer)\b"
    r")",
    re.I,
)
PROMO_SOFT_RE = re.compile(r"\b(offer|deal|deals|sale|rewards?)\b", re.I)
SOCIAL_RE = re.compile(
    r"\b(viewed your profile|new connection|people you may know|endorsed you|liked your|commented on your)\b",
    re.I,
)
SOCIAL_DOMAINS = (
    "linkedin.com",
    "facebookmail.com",
    "facebook.com",
    "instagram.com",
    "twitter.com",
    "x.com",
    "github.com",
)

SUBTYPE_LABEL = {
    "applied": "application sent",
    "call": "interview call",
    "rejection": "rejection",
    "selection": "selection",
    "offer": "offer",
    "career": "application update",
    "hackathon": "hackathon",
    "event": "event",
    "money": "money",
    "document": "document",
    "security": "security",
    "otp": "one-time code",
    "social": "notification",
    "bulk": "promotion",
}


@dataclass(frozen=True)
class Verdict:
    category: str
    subtype: str
    reason: str
    mark_delete: bool


@dataclass(frozen=True)
class Mail:
    id: str
    when: datetime.date
    sender_name: str
    email: str
    subject: str
    verdict: Verdict
    marked: bool
    attachment: bool = False
    attachment_labeled: bool = False
    snippet: str = ""


class Usage:
    def __init__(self) -> None:
        self.counts: Counter[str] = Counter()
        self.events: list[tuple[float, int]] = []
        self.alerted = False

    def clear(self) -> None:
        self.counts.clear()
        self.events.clear()
        self.alerted = False

    def add(self, method: str, n: int = 1) -> None:
        self.counts[method] += n
        self.events.append((time.monotonic(), METHOD_UNITS[method] * n))

    def units(self) -> int:
        return sum(units for _, units in self.events)

    def wait_for_room(self, cost: int) -> None:
        budget = MINUTE_QUOTA * 9 // 10
        while True:
            now = time.monotonic()
            recent = [(stamp, units) for stamp, units in self.events if stamp > now - 60]
            if not recent or sum(units for _, units in recent) + cost <= budget:
                return
            if not self.alerted:
                self.alerted = True
                print("  Pacing downloads to stay under Gmail's per-minute limit (about 90 messages a minute).", flush=True)
            time.sleep(max(recent[0][0] + 60 - now, 0.5))

    def peak_minute(self) -> int:
        best = running = start = 0
        for stamp, units in self.events:
            running += units
            while self.events[start][0] <= stamp - 60:
                running -= self.events[start][1]
                start += 1
            best = max(best, running)
        return best


USAGE = Usage()


def quota_alert(today_units: int, peak_minute: int) -> str:
    notes = []
    if today_units >= DAILY_QUOTA * 8 // 10:
        notes.append("ALERT: today is at or above 80% of the daily free limit (80,000,000 units).")
    elif today_units >= DAILY_QUOTA // 2:
        notes.append("ALERT: today is at or above 50% of the daily free limit (80,000,000 units).")
    if peak_minute > MINUTE_QUOTA * 9 // 10:
        notes.append("ALERT: this run went above 90% of the per-minute limit (6,000 units per user).")
    return " ".join(notes) if notes else "No alert."


def quota_percent(part: int, whole: int) -> str:
    value = part / whole * 100
    if value >= 0.01:
        return f"{value:.2f}%"
    return f"{value:.6f}%"


def quota_report(usage: Usage, earlier_today: int) -> str:
    this = usage.units()
    today = earlier_today + this
    lines = [
        "Gmail quota",
        "The login token is not metered. This counts Gmail API quota units from the calls this script made.",
        "Google does not send a remaining balance. The cost of each call is Google's published number.",
        f"This run: {this:,} units.",
    ]
    for method, cost in METHOD_UNITS.items():
        count = usage.counts[method]
        if count:
            lines.append(f"  {method}: {count:,} calls x {cost} = {count * cost:,}")
    lines.append(f"Today, including this run: {today:,} / {DAILY_QUOTA:,} ({quota_percent(today, DAILY_QUOTA)}).")
    lines.append("The daily count starts over each day. Older runs stay in quota_audit.csv.")
    lines.append(f"Busiest minute this run: {usage.peak_minute():,} / {MINUTE_QUOTA:,} units.")
    lines.append(quota_alert(today, usage.peak_minute()))
    return "\n".join(lines)


def record_quota(folder: Path, usage: Usage, now: datetime.datetime) -> str:
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / "quota_audit.csv"
    earlier = 0
    if path.is_file():
        with path.open(encoding="utf-8", newline="") as handle:
            for row in csv.DictReader(handle):
                if (row.get("ran_at") or "").startswith(now.date().isoformat()):
                    earlier += int(row["units"])
    report = quota_report(usage, earlier)
    new_file = not path.is_file()
    with path.open("a", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=AUDIT_FIELDS)
        if new_file:
            writer.writeheader()
        writer.writerow(
            {
                "ran_at": now.isoformat(timespec="seconds"),
                "messages_list": usage.counts["messages.list"],
                "messages_get": usage.counts["messages.get"],
                "messages_batch_modify": usage.counts["messages.batchModify"],
                "labels_list": usage.counts["labels.list"],
                "labels_create": usage.counts["labels.create"],
                "units": usage.units(),
                "peak_minute": usage.peak_minute(),
                "today_units": earlier + usage.units(),
                "alert": quota_alert(earlier + usage.units(), usage.peak_minute()),
            }
        )
    return report


def one_line(text: str) -> str:
    return re.sub(r"\s+", " ", text or "").strip()


def friendly(when: datetime.date) -> str:
    return f"{when.day} {MONTHS[when.month - 1]} {when.year}"


def three_months_before(today: datetime.date) -> datetime.date:
    month = today.month - 3
    year = today.year
    while month <= 0:
        month += 12
        year -= 1
    day = min(today.day, calendar.monthrange(year, month)[1])
    return datetime.date(year, month, day)


def past_three_months(when: datetime.date, today: datetime.date) -> bool:
    return when < three_months_before(today)


def domain_of(addr: str) -> str:
    addr = (addr or "").lower()
    return addr.rsplit("@", 1)[-1] if "@" in addr else ""


def on_domain(addr: str, item: str) -> bool:
    domain = domain_of(addr)
    return domain == item or domain.endswith("." + item)


def social_sender(addr: str) -> bool:
    return any(on_domain(addr, item) for item in SOCIAL_DOMAINS)


def platform_of(addr: str) -> str:
    for item, name in PLATFORMS:
        if on_domain(addr, item):
            return name
    return "Company or other"


def tidy_company(raw: str) -> str:
    name = COMPANY_END_RE.split(raw, 1)[0]
    words = [word for word in name.strip(" .'\"-").split() if word.lower() not in COMPANY_NOISE]
    return " ".join(words[:5])


def company_of(subject: str, snippet: str, sender: str, addr: str) -> str:
    # ponytail: guessed from subject wording, then sender name, then domain. Upgrade path: read the body.
    for text in (subject, snippet):
        for pattern in (COMPANY_AT_RE, COMPANY_PHRASE_RE):
            found = pattern.search(text or "")
            if found and tidy_company(found.group(1)):
                return tidy_company(found.group(1))
    platform = platform_of(addr)
    if platform in {"Company portal", "Company or other"}:
        name = tidy_company(re.sub(r"\bvia\b.*", "", sender or "", flags=re.I))
        if name:
            return name
    domain = domain_of(addr)
    if platform == "Company or other" and domain and domain not in FREE_MAIL:
        labels = domain.split(".")
        while len(labels) > 1 and labels[-1] in {"com", "in", "co", "io", "org", "net", "ai", "tech", "us", "uk"}:
            labels.pop()
        return labels[-1]
    return ""


def company_key(name: str) -> str:
    words = re.sub(r"[^a-z0-9 ]", " ", (name or "").lower()).split()
    return "".join(word for word in words if word not in COMPANY_SUFFIX)


def same_company(a: str, b: str) -> bool:
    if len(a) < 3 or len(b) < 3:
        return False
    return a == b or a.startswith(b) or b.startswith(a)


def application_outcomes(rows: list[dict[str, str]], today: datetime.date) -> list[dict[str, str]]:
    # ponytail: O(applications x replies) scan, fine for a few thousand job mails. Upgrade path: index replies by key.
    replies = [row for row in rows if row.get("subtype") in OUTCOME_RANK]
    keyed = [(company_key(row.get("company", "")), row) for row in replies]
    result = []
    for app in rows:
        if app.get("subtype") != "applied":
            continue
        key = company_key(app.get("company", ""))
        sent = app.get("date", "")
        hits = [row for other, row in keyed if row.get("date", "") >= sent and same_company(key, other)]
        if hits:
            last = max(hits, key=lambda row: (row.get("date", ""), OUTCOME_RANK[row["subtype"]]))
            status, updated = last["subtype"], last.get("date", "")
        else:
            try:
                age = (today - datetime.date.fromisoformat(sent)).days
            except ValueError:
                age = 0
            status, updated = ("ghosted" if age >= GHOST_DAYS else "waiting"), ""
        result.append({**app, "status": status, "updated": updated})
    return result


def looks_promo(text: str, bulk: bool, gmail_promo: bool) -> bool:
    if bulk or PROMO_RE.search(text):
        return True
    return bool(gmail_promo and PROMO_SOFT_RE.search(text))


def career_subtype(text: str) -> str | None:
    if REJECTION_RE.search(text):
        return "rejection"
    if UNFORTUNATELY_RE.search(text) and (APPLICATION_RE.search(text) or APPLIED_RE.search(text) or CANDIDATE_RE.search(text)):
        return "rejection"
    offer = OFFER_RE.search(text)
    advice = ADVICE_RE.search(text)
    if offer and not advice:
        return "offer"
    if SELECTION_RE.search(text):
        return "selection"
    direct = CALL_RE.search(text)
    if direct:
        return "call"
    if APPLIED_RE.search(text) and not advice:
        return "applied"
    if APPLICATION_RE.search(text) and not advice:
        return "career"
    return None


def event_subtype(text: str) -> str | None:
    if not EVENT_RE.search(text):
        return None
    if re.search(r"\b(hackathon|hackfest|hack day|devfolio|unstop|dare2compete)\b", text, re.I):
        return "hackathon"
    return "event"


def has_file_attachment(payload: dict | None) -> bool:
    stack = [payload] if payload else []
    while stack:
        part = stack.pop()
        if not part:
            continue
        stack.extend(part.get("parts") or [])
        filename = (part.get("filename") or "").lower()
        mime = (part.get("mimeType") or "").lower()
        if mime in DOC_MIMES or filename.endswith(DOC_SUFFIXES):
            return True
    return False


def classify(  # ponytail: subject + snippet only. A bank mail with neither goes to review and is kept. Upgrade path: fetch the body when an old mail is still "review".
    *,
    subject: str,
    sender: str,
    email: str,
    snippet: str,
    bulk: bool,
    gmail_promo: bool,
    gmail_social: bool,
    when: datetime.date,
    today: datetime.date,
    has_attachment: bool = False,
) -> Verdict:
    text = one_line(f"{subject} {sender} {snippet}").lower()
    old = past_three_months(when, today)

    def pack(category: str, subtype: str, reason: str) -> Verdict:
        mark = old and category in {"promo", "noise"} and not has_attachment
        return Verdict(category, subtype, reason, mark)

    if MONEY_RE.search(text):
        return pack("important", "money", "money")
    if STRONG_DOC_RE.search(text):
        return pack("important", "document", "document")
    if SECURITY_RE.search(text):
        return pack("important", "security", "security")
    if OTP_RE.search(text):
        return pack("noise", "otp", "one-time code")
    career = career_subtype(text)
    if career in {"offer", "selection"} and bulk and gmail_promo:
        career = None
    if career:
        return pack("interview", career, career)
    event = event_subtype(text)
    if event:
        return pack("event", event, event)
    if looks_promo(text, bulk, gmail_promo):
        reason = "mailing list" if bulk else "promotion wording"
        return pack("promo", "bulk", reason)
    if WEAK_DOC_RE.search(text):
        return pack("important", "document", "document")
    if gmail_social or social_sender(email) or SOCIAL_RE.search(text):
        return pack("noise", "social", "notification")
    return pack("review", "", "no rule matched")


def decode_mime(value: str) -> str:
    parts: list[str] = []
    for text, encoding in email.header.decode_header(value or ""):
        if isinstance(text, bytes):
            parts.append(text.decode(encoding or "utf-8", errors="replace"))
        else:
            parts.append(text)
    return "".join(parts)


def split_from(value: str) -> tuple[str, str]:
    name, addr = email.utils.parseaddr(decode_mime(value))
    name = one_line(name) or addr or "unknown"
    return name, addr.lower()


def is_bulk(headers: dict[str, str]) -> bool:
    if headers.get("list-unsubscribe") or headers.get("list-id"):
        return True
    return (headers.get("precedence") or "").lower() in {"bulk", "list", "junk"}


def date_from_ms(ms: int) -> datetime.date:
    return datetime.datetime.fromtimestamp(ms / 1000).date()


def excel_safe(value: str) -> str:
    if value.startswith(("=", "+", "-", "@")):
        return "'" + value
    return value


def write_outputs(folder: Path, mails: list[Mail], name: str = "mail_index.csv") -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    index_path = folder / name
    ordered = sorted(mails, key=lambda mail: (mail.when, mail.id), reverse=True)
    with index_path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.writer(handle)
        writer.writerow(["date", "category", "subtype", "mark_delete", "attachment", "sender", "email", "subject", "reason", "id", "company"])
        for mail in ordered:
            company = ""
            if mail.verdict.category == "interview":
                company = company_of(mail.subject, mail.snippet, mail.sender_name, mail.email)
            writer.writerow(
                [
                    mail.when.isoformat(),
                    mail.verdict.category,
                    mail.verdict.subtype,
                    "yes" if mail.verdict.mark_delete else "no",
                    "yes" if mail.attachment else "no",
                    excel_safe(mail.sender_name),
                    mail.email,
                    excel_safe(mail.subject),
                    mail.verdict.reason,
                    mail.id,
                    excel_safe(company),
                ]
            )
    return index_path


def open_db(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS msgs (
            id TEXT PRIMARY KEY,
            internal_ms INTEGER NOT NULL,
            sender TEXT NOT NULL,
            email TEXT NOT NULL,
            subject TEXT NOT NULL,
            snippet TEXT NOT NULL,
            bulk INTEGER NOT NULL,
            gmail_promo INTEGER NOT NULL,
            gmail_social INTEGER NOT NULL,
            marked INTEGER NOT NULL,
            attachment INTEGER,
            attachment_labeled INTEGER NOT NULL DEFAULT 0
        )
        """
    )
    cols = {row[1] for row in conn.execute("PRAGMA table_info(msgs)")}
    if "attachment" not in cols:
        conn.execute("ALTER TABLE msgs ADD COLUMN attachment INTEGER")
    if "attachment_labeled" not in cols:
        conn.execute("ALTER TABLE msgs ADD COLUMN attachment_labeled INTEGER NOT NULL DEFAULT 0")
    conn.commit()
    return conn


def require_google() -> None:
    global HttpError, build, Credentials, InstalledAppFlow, Request
    try:
        from google.auth.transport.requests import Request as RequestCls
        from google.oauth2.credentials import Credentials as CredentialsCls
        from google_auth_oauthlib.flow import InstalledAppFlow as FlowCls
        from googleapiclient.discovery import build as build_fn
        from googleapiclient.errors import HttpError as HttpErrorCls
    except ImportError as err:
        raise SystemExit("Missing Gmail libraries. Run: pip install -r requirements.txt") from err
    Request = RequestCls
    Credentials = CredentialsCls
    InstalledAppFlow = FlowCls
    build = build_fn
    HttpError = HttpErrorCls


def setup_help(credentials_path: Path) -> str:
    return (
        "Gmail is not connected yet.\n"
        "1. Create a project: https://console.cloud.google.com/projectcreate\n"
        "2. Enable the Gmail API: https://console.cloud.google.com/apis/library/gmail.googleapis.com\n"
        "3. OAuth consent screen, External, add your Gmail as a test user:\n"
        "   https://console.cloud.google.com/apis/credentials/consent\n"
        "4. Create an OAuth client ID, type Desktop app:\n"
        "   https://console.cloud.google.com/apis/credentials\n"
        f"5. Download the JSON and save it as:\n   {credentials_path}\n"
        "6. Run: python mail_agent.py --limit 100\n"
        "A browser window will ask for access. Google's wording mentions deleting mail.\n"
        "This script only reads mail and adds or removes the Agent/MarkDelete label."
    )


def execute(request, what: str, method: str):
    delay = 1
    for attempt in range(5):
        try:
            USAGE.add(method)
            return request.execute()
        except HttpError as err:
            status = getattr(err.resp, "status", None)
            if status in {429, 500, 503} and attempt < 4:
                time.sleep(delay)
                delay *= 2
                continue
            raise SystemExit(f"Gmail API failed while {what}: {err}") from err
    raise SystemExit(f"Gmail API failed while {what}")


def connect(credentials_path: Path, token_path: Path, interactive: bool = True):
    require_google()
    if not credentials_path.is_file():
        raise SystemExit(setup_help(credentials_path))
    creds = None
    if token_path.is_file():
        creds = Credentials.from_authorized_user_file(str(token_path), SCOPES)
    if creds and creds.expired and creds.refresh_token:
        try:
            creds.refresh(Request())
        except Exception:
            creds = None
    if not creds or not creds.valid:
        if not interactive:
            raise SystemExit("Gmail login expired. Run python mail_agent.py --today once to sign in again.")
        flow = InstalledAppFlow.from_client_secrets_file(str(credentials_path), SCOPES)
        creds = flow.run_local_server(port=0)
    token_path.write_text(creds.to_json(), encoding="utf-8")
    return build("gmail", "v1", credentials=creds)


TOAST_PS = (
    "[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null;"
    "$x = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent("
    "[Windows.UI.Notifications.ToastTemplateType]::ToastText02);"
    "$t = $x.GetElementsByTagName('text');"
    "$t.Item(0).AppendChild($x.CreateTextNode($env:MAIL_AGENT_TITLE)) > $null;"
    "$t.Item(1).AppendChild($x.CreateTextNode($env:MAIL_AGENT_TEXT)) > $null;"
    "[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("
    "'{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\WindowsPowerShell\\v1.0\\powershell.exe')"
    ".Show([Windows.UI.Notifications.ToastNotification]::new($x))"
)


def notify(title: str, text: str) -> None:
    print(f"Notification: {title}: {text}", flush=True)
    if sys.platform != "win32":
        return
    # Email text goes through environment variables so a subject can never run as PowerShell code.
    env = {**os.environ, "MAIL_AGENT_TITLE": title, "MAIL_AGENT_TEXT": text}
    try:
        subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", TOAST_PS],
            env=env, timeout=60, check=False, creationflags=subprocess.CREATE_NO_WINDOW,
        )
    except (OSError, subprocess.SubprocessError) as err:
        print(f"Notification failed: {err}", flush=True)


def daily_message(new_mails: list[Mail]) -> tuple[str, str]:
    jobs = [mail for mail in new_mails if mail.verdict.category == "interview"]
    names = dict(JOB_STAGES)
    if jobs:
        counts = Counter(mail.verdict.subtype for mail in jobs)
        parts = [f"{counts[key]} {label.lower()}" for key, label in JOB_STAGES if counts[key]]
        top = next((mail for key in ("offer", "selection", "call", "rejection", "applied", "career")
                    for mail in jobs if mail.verdict.subtype == key), jobs[0])
        return "Mail agent: job mail", f"{', '.join(parts)}. {names.get(top.verdict.subtype, '')}: {top.subject}"[:250]
    counts = Counter(mail.verdict.category for mail in new_mails)
    return (
        "Mail agent: daily scan",
        f"{len(new_mails)} new mails, {counts['promo']} promotions, {counts['event']} events. No job mail.",
    )


def mailbox_query(today_only: bool, today: datetime.date) -> str:
    if not today_only:
        return QUERY
    start = today - datetime.timedelta(days=1)
    end = today + datetime.timedelta(days=1)
    return f"{QUERY} after:{start.strftime('%Y/%m/%d')} before:{end.strftime('%Y/%m/%d')}"


def list_ids(service, limit: int, query: str = QUERY) -> list[str]:
    ids: list[str] = []
    token = None
    while True:
        body = execute(
            service.users().messages().list(userId="me", q=query, maxResults=500, pageToken=token),
            "listing mail",
            "messages.list",
        )
        ids.extend(item["id"] for item in body.get("messages", []))
        print(f"  listed {len(ids)}", flush=True)
        if limit and len(ids) >= limit:
            return ids[:limit]
        token = body.get("nextPageToken")
        if not token:
            return ids


def find_label(service, name: str) -> str | None:
    body = execute(service.users().labels().list(userId="me"), "reading labels", "labels.list")
    for label in body.get("labels", []):
        if label.get("name") == name:
            return label["id"]
    return None


def ensure_label(service, name: str) -> str:
    found = find_label(service, name)
    if found:
        return found
    created = execute(
        service.users().labels().create(
            userId="me",
            body={
                "name": name,
                "labelListVisibility": "labelShow",
                "messageListVisibility": "show",
            },
        ),
        f"creating {name}",
        "labels.create",
    )
    return created["id"]


def header_map(message: dict) -> dict[str, str]:
    headers = message.get("payload", {}).get("headers", [])
    return {item["name"].lower(): item["value"] for item in headers}


def parse_message(message: dict, mark_label_id: str | None, attach_label_id: str | None) -> dict | None:
    if "internalDate" not in message:
        return None
    headers = header_map(message)
    sender, addr = split_from(headers.get("from", ""))
    labels = set(message.get("labelIds") or [])
    return {
        "id": message["id"],
        "internal_ms": int(message["internalDate"]),
        "sender": sender,
        "email": addr,
        "subject": one_line(decode_mime(headers.get("subject", ""))) or "(no subject)",
        "snippet": one_line(message.get("snippet", "")),
        "bulk": 1 if is_bulk(headers) else 0,
        "gmail_promo": 1 if "CATEGORY_PROMOTIONS" in labels else 0,
        "gmail_social": 1 if "CATEGORY_SOCIAL" in labels else 0,
        "marked": 1 if mark_label_id and mark_label_id in labels else 0,
        "attachment": 1 if has_file_attachment(message.get("payload")) else 0,
        "attachment_labeled": 1 if attach_label_id and attach_label_id in labels else 0,
    }


def fetch_chunk(service, ids: list[str]) -> tuple[dict, list[str]]:
    found: dict = {}
    bad: list[str] = []

    def callback(request_id, response, exception):
        if exception is None:
            found[request_id] = response
        else:
            bad.append(request_id)

    batch = service.new_batch_http_request(callback=callback)
    for mid in ids:
        batch.add(
            service.users().messages().get(
                userId="me",
                id=mid,
                format="full",
                fields=MESSAGE_FIELDS,
            ),
            request_id=mid,
        )
    USAGE.add("messages.get", len(ids))
    try:
        batch.execute()
    except HttpError:
        return {}, list(ids)
    return found, bad


def fetch_messages(service, conn: sqlite3.Connection, ids: list[str], mark_label_id: str | None, attach_label_id: str | None) -> None:
    failed: list[str] = []
    total = len(ids)
    cost = METHOD_UNITS["messages.get"]
    for index in range(0, total, FETCH_BATCH):
        chunk = ids[index : index + FETCH_BATCH]
        USAGE.wait_for_room(len(chunk) * cost)
        found, bad = fetch_chunk(service, chunk)
        if bad:
            time.sleep(2)
            USAGE.wait_for_room(len(bad) * cost)
            retry, bad = fetch_chunk(service, bad)
            found.update(retry)
        parsed = [item for item in (parse_message(m, mark_label_id, attach_label_id) for m in found.values()) if item]
        store_messages(conn, parsed)
        failed.extend(bad)
        done = min(index + FETCH_BATCH, total)
        if done == total or done % 200 == 0:
            print(f"  downloaded {done}/{total}, quota so far {USAGE.units():,} units", flush=True)
    if failed:
        print(f"  skipped {len(failed)} messages that Gmail did not return; the next run tries them again", flush=True)


def store_messages(conn: sqlite3.Connection, rows: list[dict]) -> None:
    conn.executemany(
        """
        INSERT INTO msgs (
            id, internal_ms, sender, email, subject, snippet, bulk, gmail_promo, gmail_social, marked,
            attachment, attachment_labeled
        ) VALUES (
            :id, :internal_ms, :sender, :email, :subject, :snippet, :bulk, :gmail_promo, :gmail_social, :marked,
            :attachment, :attachment_labeled
        )
        ON CONFLICT(id) DO UPDATE SET
            internal_ms=excluded.internal_ms,
            sender=excluded.sender,
            email=excluded.email,
            subject=excluded.subject,
            snippet=excluded.snippet,
            bulk=excluded.bulk,
            gmail_promo=excluded.gmail_promo,
            gmail_social=excluded.gmail_social,
            marked=excluded.marked,
            attachment=excluded.attachment,
            attachment_labeled=excluded.attachment_labeled
        """,
        rows,
    )
    conn.commit()


def load_mails(conn: sqlite3.Connection, ids: list[str], today: datetime.date) -> list[Mail]:
    wanted = set(ids)
    mails: list[Mail] = []
    for row in conn.execute("SELECT * FROM msgs"):
        if row["id"] not in wanted:
            continue
        when = date_from_ms(row["internal_ms"])
        verdict = classify(
            subject=row["subject"],
            sender=row["sender"],
            email=row["email"],
            snippet=row["snippet"],
            bulk=bool(row["bulk"]),
            gmail_promo=bool(row["gmail_promo"]),
            gmail_social=bool(row["gmail_social"]),
            when=when,
            today=today,
            has_attachment=bool(row["attachment"]),
        )
        mails.append(
            Mail(
                id=row["id"],
                when=when,
                sender_name=row["sender"],
                email=row["email"],
                subject=row["subject"],
                verdict=verdict,
                marked=bool(row["marked"]),
                attachment=bool(row["attachment"]),
                attachment_labeled=bool(row["attachment_labeled"]),
                snippet=row["snippet"],
            )
        )
    return mails


def set_column(conn: sqlite3.Connection, ids: list[str], column: str, value: int) -> None:
    # ponytail: trusts our last label write. A label removed by hand in Gmail stays off until the rule stops matching. Upgrade path: refetch labelIds.
    if column not in {"marked", "attachment_labeled"}:
        raise ValueError(column)
    conn.executemany(f"UPDATE msgs SET {column} = ? WHERE id = ?", [(value, mid) for mid in ids])
    conn.commit()


def sync_label(service, label_id: str, conn: sqlite3.Connection, mails: list[Mail], want, already, column: str, what: str) -> tuple[int, int]:
    add_ids = [mail.id for mail in mails if want(mail) and not already(mail)]
    remove_ids = [mail.id for mail in mails if already(mail) and not want(mail)]
    for group in chunks(add_ids, 1000):
        execute(
            service.users().messages().batchModify(userId="me", body={"ids": group, "addLabelIds": [label_id]}),
            f"adding {what}",
            "messages.batchModify",
        )
        set_column(conn, group, column, 1)
    for group in chunks(remove_ids, 1000):
        execute(
            service.users().messages().batchModify(userId="me", body={"ids": group, "removeLabelIds": [label_id]}),
            f"removing {what}",
            "messages.batchModify",
        )
        set_column(conn, group, column, 0)
    return len(add_ids), len(remove_ids)


def chunks(items: list[str], size: int):
    for index in range(0, len(items), size):
        yield items[index : index + size]


def self_check() -> None:
    today = datetime.date(2026, 11, 5)
    assert three_months_before(today) == datetime.date(2026, 8, 5)
    assert three_months_before(datetime.date(2026, 5, 31)) == datetime.date(2026, 2, 28)
    assert three_months_before(datetime.date(2024, 5, 31)) == datetime.date(2024, 2, 29)
    old = datetime.date(2026, 1, 1)
    edge_keep = datetime.date(2026, 8, 5)
    edge_mark = datetime.date(2026, 8, 4)
    new = datetime.date(2026, 11, 1)

    def expect(subject, category, mark, subtype, **kwargs):
        verdict = classify(
            subject=subject,
            sender=kwargs.pop("sender", "Ada"),
            email=kwargs.pop("email", "ada@example.com"),
            snippet=kwargs.pop("snippet", ""),
            bulk=kwargs.pop("bulk", False),
            gmail_promo=kwargs.pop("gmail_promo", False),
            gmail_social=kwargs.pop("gmail_social", False),
            when=kwargs.pop("when"),
            today=today,
            has_attachment=kwargs.pop("has_attachment", False),
        )
        assert verdict.category == category, (subject, verdict)
        assert verdict.mark_delete is mark, (subject, verdict)
        assert verdict.subtype == subtype, (subject, verdict)

    expect("Amount credited to your account", "important", False, "money", when=old, bulk=True)
    expect("Your invoice is attached", "important", False, "document", when=old)
    expect("Available balance is ready", "important", False, "money", when=old, snippet="available balance INR 20000")
    expect("Credit card statement is ready", "important", False, "money", when=old)
    expect("Flat 50% off - Rs. 499", "promo", True, "bulk", when=old)
    expect("Flat 50% off - Rs. 499", "promo", False, "bulk", when=old, has_attachment=True)
    assert has_file_attachment({"mimeType": "application/pdf", "filename": "note.pdf"})
    assert has_file_attachment({"parts": [{"mimeType": "text/plain"}, {"filename": "sheet.xlsx", "mimeType": "application/octet-stream"}]})
    assert not has_file_attachment({"parts": [{"filename": "logo.png", "mimeType": "image/png"}]})
    assert not has_file_attachment(None)
    expect("Pre-approved credit card, 50% off joining fee", "promo", True, "bulk", when=old)
    expect("Flat 60% off on shoes", "promo", False, "bulk", when=new)
    expect("Flat 60% off on shoes", "promo", False, "bulk", when=edge_keep)
    expect("Flat 60% off on shoes", "promo", True, "bulk", when=edge_mark)
    expect("Weekly deals", "promo", True, "bulk", when=old, bulk=True)
    expect("Interview is scheduled for Monday", "interview", False, "call", when=old)
    expect("We regret to inform you we are moving forward with other candidates", "interview", False, "rejection", when=old)
    expect("You have been shortlisted for the role", "interview", False, "selection", when=new)
    expect("Your offer letter is attached", "interview", False, "offer", when=old)
    expect("Shubh Dhanteras, invest in an offer letter", "promo", False, "bulk", when=new, bulk=True, gmail_promo=True)
    expect("Prajwal, your application was sent to Acme", "interview", False, "applied", when=old, bulk=True)
    expect("You have successfully applied to SDE 1 at Zeta", "interview", False, "applied", when=new)
    expect("Thank you for applying. Unfortunately we will not be moving forward", "interview", False, "rejection", when=new)
    expect("Check out jobs applied by other Software Development Engineer 1", "review", False, "", when=new)
    assert platform_of("jobs-noreply@linkedin.com") == "LinkedIn"
    assert platform_of("info@naukri.com") == "Naukri"
    assert platform_of("no-reply@us.greenhouse-mail.io") == "Company portal"
    assert platform_of("hr@acme.com") == "Company or other"
    assert platform_of("evil@notlinkedin.com") == "Company or other"
    expect("How to crack interviews", "promo", True, "bulk", when=old, bulk=True)
    expect("Hackathon registration closes Friday", "event", False, "hackathon", when=new)
    expect("Design webinar this Friday", "event", False, "event", when=old)
    expect("123456 is your OTP for login", "noise", True, "otp", when=old)
    expect("New sign-in on your account", "important", False, "security", when=old)
    expect("Someone viewed your profile", "noise", True, "social", when=old, email="jobs-noreply@linkedin.com")
    expect("Hello from Priya", "review", False, "", when=old)
    expect("Assignment 3 is posted", "review", False, "", when=old)
    assert excel_safe("=cmd") == "'=cmd"

    def sample(mid, when, sender, addr, subject, **kwargs):
        attached = kwargs.get("attachment", False)
        verdict = classify(
            subject=subject,
            sender=sender,
            email=addr,
            snippet="",
            bulk=kwargs.get("bulk", False),
            gmail_promo=False,
            gmail_social=False,
            when=when,
            today=today,
            has_attachment=attached,
        )
        return Mail(mid, when, sender, addr, subject, verdict, False, attachment=attached)

    mails = [
        sample("1", new, "Amazon", "deals@amazon.in", "Flat 60% off on shoes"),
        sample("7", new, "Amazon", "deals@amazon.in", "Weekend deals", bulk=True),
        sample("2", old, "Myntra", "news@myntra.com", "End of season sale", bulk=True),
        sample("3", old, "HDFC Bank", "alerts@hdfc.example", "Amount credited to your account"),
        sample("4", new, "Razorpay", "jobs@razorpay.com", "Interview is scheduled for Monday"),
        sample("5", new, "Devfolio", "hello@devfolio.co", "Hackathon registration closes Friday"),
        sample("6", old, "Flipkart", "deals@flipkart.com", "Festival price list", bulk=True, attachment=True),
        sample("8", new, "<b>Spam</b>", "x@y.z", "Hello"),
    ]
    with tempfile.TemporaryDirectory() as folder:
        write_outputs(Path(folder), mails)
        page = render_page(load_index(Path(folder)), [], "Scan finished.")
    assert "Safe mode: nothing is deleted" in page
    assert "Only today's mail" in page
    assert "Amount credited to your account" in page
    assert "2 mails" in page
    assert "1 marked" in page
    assert "interview call" in page
    assert "hackathon" in page
    assert 'data-marked="no" data-attach="yes"' in page
    assert "&lt;b&gt;Spam&lt;/b&gt;" in page and "<b>Spam</b>" not in page
    assert "Quota appears here after the first run." in page
    assert "No scan yet" in render_page([], [], "")
    assert page.count('<section class="card"><h2>') >= 6
    expect("Update on your application", "interview", False, "rejection", when=new, snippet="Unfortunately we have decided")
    expect("Unfortunately the meetup is cancelled", "event", False, "event", when=new)
    assert company_of("Prajwal, your application was sent to Acme Corp", "", "LinkedIn", "jobs-noreply@linkedin.com") == "Acme Corp"
    assert company_of("You have successfully applied to SDE 1 at Zeta", "", "Naukri", "info@naukri.com") == "Zeta"
    assert company_of("Thank you for your interest in Acme Technologies Pvt Ltd", "", "x", "x@gmail.com") == "Acme Technologies Pvt Ltd"
    assert company_of("Update on your application", "", "Razorpay Careers", "no-reply@greenhouse-mail.io") == "Razorpay"
    assert company_of("Update on your application", "", "", "talent@careers.swiggy.in") == "swiggy"
    assert company_of("Your application", "", "LinkedIn", "jobs-noreply@linkedin.com") == ""
    assert same_company(company_key("Acme Corp"), company_key("Acme Technologies Pvt Ltd"))
    assert not same_company(company_key("Acme"), company_key("Zeta"))

    def job(mid, date, subtype, company, addr="jobs-noreply@linkedin.com"):
        return {"id": mid, "date": date, "subtype": subtype, "company": company, "email": addr, "sender": "", "subject": mid}

    day = datetime.date(2026, 11, 13)
    job_rows = [
        job("a1", "2026-11-10", "applied", "Fresh Co"),
        job("a2", "2026-09-01", "applied", "Acme Corp"),
        job("a3", "2026-08-01", "applied", "Zeta", "info@naukri.com"),
        job("r0", "2026-07-01", "rejection", "Zeta", "hr@zeta.com"),
    ]
    status = {app["id"]: app["status"] for app in application_outcomes(job_rows, day)}
    assert status == {"a1": "waiting", "a2": "ghosted", "a3": "ghosted"}, status
    job_rows.append(job("r1", "2026-11-12", "rejection", "Acme", "hr@acme.com"))
    job_rows.append(job("s1", "2026-11-12", "selection", "Zeta Labs", "hr@zeta.com"))
    status = {app["id"]: app["status"] for app in application_outcomes(job_rows, day)}
    assert status == {"a1": "waiting", "a2": "rejection", "a3": "selection"}, status
    totals, by_platform = job_counts(application_outcomes(job_rows, day))
    assert totals["rejection"] == 1 and totals["selection"] == 1 and totals["ghosted"] == 0
    assert by_platform["LinkedIn"]["waiting"] == 1 and by_platform["Naukri"]["selection"] == 1
    jobs_page = render_jobs_page(job_rows, [], day)
    assert 'aria-current="page">Jobs' in jobs_page
    assert "Ghosted" in jobs_page and "stage-waiting" in jobs_page
    assert "No job mail yet" in render_jobs_page([], [])
    title, text = daily_message(mails)
    assert title == "Mail agent: job mail" and text.startswith("1 interview call. Interview call: Interview is"), text
    title, text = daily_message(mails[:3])
    assert title == "Mail agent: daily scan" and "3 new mails, 3 promotions" in text, text
    with tempfile.TemporaryDirectory() as folder:
        conn = open_db(Path(folder) / "t.db")
        row = {"id": "m1", "internal_ms": 1_700_000_000_000, "sender": "Acme Careers", "email": "hr@acme.com",
               "subject": "Thank you for applying to Acme", "snippet": "", "bulk": 0, "gmail_promo": 0,
               "gmail_social": 0, "marked": 0, "attachment": 0, "attachment_labeled": 0}
        store_messages(conn, [row])
        store_messages(conn, [row])
        loaded = load_mails(conn, ["m1"], today)
        assert len(loaded) == 1 and loaded[0].verdict.subtype == "applied"
        write_outputs(Path(folder), loaded, "jobs.csv")
        assert load_jobs(Path(folder))[0]["company"] == "Acme"
        conn.close()
    sample_usage = Usage()
    sample_usage.add("messages.get", 2)
    sample_usage.add("messages.list", 1)
    assert sample_usage.units() == 125
    assert sample_usage.peak_minute() == 125
    assert quota_alert(0, 100) == "No alert."
    assert "daily free limit" in quota_alert(DAILY_QUOTA // 2, 0)
    assert "per-minute" in quota_alert(0, MINUTE_QUOTA)
    assert quota_alert(0, MINUTE_QUOTA * 9 // 10) == "No alert."
    assert "80,000,000" in quota_report(sample_usage, 0)
    assert "No alert." in quota_report(sample_usage, 0)
    with tempfile.TemporaryDirectory() as folder:
        when = datetime.datetime(2026, 11, 10, 12, 0, 0)
        record_quota(Path(folder), sample_usage, when)
        again = Usage()
        again.add("messages.list", 1)
        report = record_quota(Path(folder), again, when)
        assert "Today, including this run: 130 /" in report
        saved = (Path(folder) / "quota_audit.csv").read_text(encoding="utf-8")
        assert saved.count("2026-11-10") == 2
        quota_page = render_page([], load_runs(Path(folder)), "Limit must be a number.", ok=False)
    assert "130 / 80,000,000 units" in quota_page
    assert "10 Nov 2026, 12:00" in quota_page
    assert 'class="notice err"' in quota_page
    assert "No alert." in quota_page
    today_query = mailbox_query(True, datetime.date(2026, 11, 10))
    assert "after:2026/11/09" in today_query
    assert "before:2026/11/11" in today_query
    assert mailbox_query(False, datetime.date(2026, 11, 10)) == QUERY


def read_rows(path: Path) -> list[dict[str, str]]:
    if not path.is_file():
        return []
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def load_index(folder: Path) -> list[dict[str, str]]:
    return read_rows(folder / "mail_index.csv")


def load_jobs(folder: Path) -> list[dict[str, str]]:
    return read_rows(folder / "jobs.csv")


CATEGORY_NAMES = {
    "interview": "Interview",
    "event": "Event",
    "important": "Important",
    "promo": "Promotion",
    "noise": "Notification",
    "review": "Not sure",
}
TABLE_CAP = 500
PANEL_CAP = 200

PAGE_CSS = """
:root {
  --bg: #f5f6f8; --card: #ffffff; --line: #e4e7ec; --text: #111827; --muted: #5b6474;
  --accent: #4338ca; --accent-soft: #eef2ff; --ok: #047857; --ok-soft: #ecfdf5;
  --bad: #b91c1c; --bad-soft: #fef2f2; --warn: #b45309; --warn-soft: #fffbeb;
}
* { box-sizing: border-box; }
[hidden] { display: none !important; }
body { margin: 0; background: var(--bg); color: var(--text);
  font: 15px/1.5 "Segoe UI", system-ui, -apple-system, sans-serif; }
a { color: var(--accent); }
.top { background: var(--card); border-bottom: 1px solid var(--line); }
.top-inner, main { max-width: 1180px; margin: 0 auto; padding: 0 24px; }
.top-inner { display: flex; align-items: center; gap: 16px; min-height: 68px; flex-wrap: wrap; }
.brand { display: flex; align-items: center; gap: 12px; margin-right: auto; }
.logo { width: 36px; height: 36px; border-radius: 10px; background: var(--accent); color: #fff;
  display: grid; place-items: center; font-weight: 700; }
.brand h1 { font-size: 18px; margin: 0; }
.brand p { margin: 0; color: var(--muted); font-size: 13px; }
.pill { display: inline-flex; align-items: center; gap: 6px; padding: 5px 11px; border-radius: 999px;
  font-size: 13px; font-weight: 600; background: var(--ok-soft); color: var(--ok); }
.pill.dim { background: #f1f3f6; color: var(--muted); font-weight: 500; }
.dot { width: 7px; height: 7px; border-radius: 50%; background: currentColor; }
main { padding-top: 24px; padding-bottom: 48px; display: grid; gap: 20px; }
.card { background: var(--card); border: 1px solid var(--line); border-radius: 14px; padding: 20px; }
.card h2 { font-size: 15px; margin: 0 0 4px; }
.card .sub { margin: 0 0 14px; color: var(--muted); font-size: 13px; }
.run { display: grid; grid-template-columns: 1fr 1fr 180px auto; gap: 12px; align-items: stretch; }
.run fieldset { display: contents; border: 0; margin: 0; padding: 0; }
.mode { display: flex; gap: 10px; align-items: flex-start; border: 1px solid var(--line); border-radius: 12px;
  padding: 12px 14px; cursor: pointer; }
.mode:has(input:checked) { border-color: var(--accent); background: var(--accent-soft); }
.mode input { margin-top: 3px; accent-color: var(--accent); }
.mode strong { display: block; font-size: 14px; }
.mode small { color: var(--muted); font-size: 12.5px; }
.limit { display: flex; flex-direction: column; gap: 4px; font-size: 12.5px; color: var(--muted); }
.limit input { font: inherit; font-size: 15px; color: var(--text); padding: 9px 11px; border: 1px solid var(--line);
  border-radius: 10px; width: 100%; }
.limit input:disabled { background: #f3f4f6; color: #9ca3af; }
button.go { font: inherit; font-weight: 600; border: 0; border-radius: 12px; padding: 0 22px; background: var(--accent);
  color: #fff; cursor: pointer; min-height: 46px; }
button.go:hover { background: #3730a3; }
button.go:disabled { opacity: 0.7; cursor: wait; }
:focus-visible { outline: 3px solid #a5b4fc; outline-offset: 2px; }
.hint { margin: 12px 0 0; color: var(--muted); font-size: 12.5px; }
code { background: #f1f3f6; padding: 1px 6px; border-radius: 6px; font-size: 12.5px; }
.notice { border-radius: 12px; padding: 12px 16px; font-weight: 500; }
.notice.ok { background: var(--ok-soft); color: var(--ok); border: 1px solid #a7f3d0; }
.notice.err { background: var(--bad-soft); color: var(--bad); border: 1px solid #fecaca; }
.stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; }
.stat { background: var(--card); border: 1px solid var(--line); border-radius: 12px; padding: 14px 16px;
  border-top: 3px solid var(--c, #cbd5e1); }
.stat-label { display: block; color: var(--muted); font-size: 12.5px; }
.stat-value { display: block; font-size: 26px; font-weight: 700; margin-top: 2px; }
.s-interview { --c: #7c3aed; } .s-event { --c: #2563eb; } .s-important { --c: #d97706; }
.s-attach { --c: #0d9488; } .s-promo { --c: #64748b; } .s-noise { --c: #94a3b8; }
.s-review { --c: #db2777; } .s-marked { --c: #dc2626; } .s-all { --c: var(--accent); }
.panels { display: grid; grid-template-columns: repeat(auto-fit, minmax(340px, 1fr)); gap: 20px; }
.panels .card { height: 420px; display: flex; flex-direction: column; min-width: 0; }
.panels .list, .panels .empty { flex: 1; min-height: 0; overflow-y: auto; padding-right: 6px; }
.panels .list::-webkit-scrollbar { width: 8px; }
.panels .list::-webkit-scrollbar-thumb { background: #d6d9e0; border-radius: 999px; }
.panels .count { margin-left: 8px; font-size: 12px; font-weight: 600; color: var(--muted); }
.nav { display: flex; gap: 4px; background: #f1f3f6; padding: 4px; border-radius: 12px; }
.nav a { text-decoration: none; color: var(--muted); font-weight: 600; font-size: 14px; padding: 7px 14px; border-radius: 9px; }
.nav a[aria-current="page"] { background: var(--card); color: var(--text); box-shadow: 0 1px 2px rgba(0, 0, 0, 0.08); }
.stage-applied { background: #e0e7ff; color: #3730a3; } .stage-call { background: #f3e8ff; color: #6b21a8; }
.stage-selection { background: #dcfce7; color: #166534; } .stage-offer { background: #d1fae5; color: #065f46; }
.stage-rejection { background: #fee2e2; color: #991b1b; } .stage-career { background: #f1f5f9; color: #475569; }
.s-applied { --c: #4f46e5; } .s-call { --c: #7c3aed; } .s-selection { --c: #16a34a; }
.s-offer { --c: #059669; } .s-rejection { --c: #dc2626; } .s-career { --c: #94a3b8; }
.stage-ghosted { background: #e5e7eb; color: #374151; } .stage-waiting { background: #fef3c7; color: #92400e; }
.s-ghosted { --c: #6b7280; } .s-waiting { --c: #d97706; }
td.num, th.num { text-align: right; font-variant-numeric: tabular-nums; }
.list { list-style: none; margin: 0; padding: 0; }
.item, .group { display: flex; gap: 12px; align-items: flex-start; padding: 10px 0; border-top: 1px solid var(--line); }
.list li:first-child { border-top: 0; padding-top: 2px; }
.item-main { min-width: 0; flex: 1; }
.subject { font-weight: 600; font-size: 14px; overflow-wrap: anywhere; }
.meta { color: var(--muted); font-size: 12.5px; overflow-wrap: anywhere; }
.n { white-space: nowrap; font-size: 12.5px; font-weight: 600; background: #f1f3f6; color: #374151;
  padding: 2px 9px; border-radius: 999px; }
.empty { color: var(--muted); font-size: 13.5px; margin: 0; padding: 6px 0; }
.more { color: var(--muted); font-size: 12.5px; margin: 8px 0 0; }
.tag { display: inline-block; white-space: nowrap; font-size: 12px; font-weight: 600; padding: 2px 9px;
  border-radius: 999px; background: #f1f5f9; color: #475569; }
.tag::first-letter { text-transform: uppercase; }
.t-interview { background: #f3e8ff; color: #6b21a8; } .t-event { background: #dbeafe; color: #1e40af; }
.t-important { background: #fef3c7; color: #92400e; } .t-promo { background: #f1f5f9; color: #475569; }
.t-noise { background: #f3f4f6; color: #4b5563; } .t-review { background: #fce7f3; color: #9d174d; }
.flag { display: inline-block; white-space: nowrap; font-size: 12px; font-weight: 600; padding: 2px 9px;
  border-radius: 999px; background: var(--bad-soft); color: var(--bad); margin: 0 4px 4px 0; }
.flag.f-attach { background: #ccfbf1; color: #115e59; }
.tools { display: flex; gap: 10px; flex-wrap: wrap; align-items: center; margin-bottom: 12px; }
.search { flex: 1 1 260px; font: inherit; padding: 9px 12px; border: 1px solid var(--line); border-radius: 10px; }
.chips { display: flex; gap: 6px; flex-wrap: wrap; }
.chip { font: inherit; font-size: 13px; padding: 6px 12px; border-radius: 999px; border: 1px solid var(--line);
  background: var(--card); color: var(--text); cursor: pointer; }
.chip[aria-pressed="true"] { background: var(--text); color: #fff; border-color: var(--text); }
.shown { color: var(--muted); font-size: 12.5px; margin-left: auto; }
.table-wrap { overflow-x: auto; border: 1px solid var(--line); border-radius: 12px; }
table { width: 100%; border-collapse: collapse; font-size: 14px; }
th { text-align: left; font-size: 12px; text-transform: uppercase; letter-spacing: 0.04em; color: var(--muted);
  background: #f9fafb; padding: 10px 12px; border-bottom: 1px solid var(--line); }
td { padding: 10px 12px; border-bottom: 1px solid var(--line); vertical-align: top; }
tbody tr:last-child td { border-bottom: 0; }
tbody tr:hover { background: #fafbff; }
.nowrap { white-space: nowrap; color: var(--muted); }
td.who { min-width: 240px; }
td.who .meta { overflow-wrap: normal; word-break: normal; }
.quota { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 16px; }
.meter-label { display: flex; justify-content: space-between; font-size: 13px; color: var(--muted); margin-bottom: 6px; }
.meter-label strong { color: var(--text); }
.meter { height: 10px; background: #eef0f4; border-radius: 999px; overflow: hidden; }
.meter span { display: block; height: 100%; background: var(--accent); border-radius: 999px; }
.meter.hot span { background: var(--warn); }
.alert { margin-top: 14px; border-radius: 10px; padding: 10px 14px; font-size: 13.5px; }
.alert.ok { background: var(--ok-soft); color: var(--ok); }
.alert.warn { background: var(--warn-soft); color: var(--warn); }
.history { margin-top: 16px; }
.overlay { position: fixed; inset: 0; background: rgba(17, 24, 39, 0.45); display: grid; place-items: center; z-index: 10; }
.busy { background: var(--card); border-radius: 16px; padding: 24px 28px; display: flex; gap: 16px; align-items: center;
  max-width: 420px; box-shadow: 0 20px 50px rgba(0, 0, 0, 0.2); }
.busy p { margin: 4px 0 0; color: var(--muted); font-size: 13.5px; }
.spinner { width: 34px; height: 34px; border-radius: 50%; border: 4px solid #e0e7ff; border-top-color: var(--accent);
  animation: spin 0.8s linear infinite; flex: none; }
@keyframes spin { to { transform: rotate(360deg); } }
@media (prefers-reduced-motion: reduce) { .spinner { animation-duration: 2.4s; } }
@media (max-width: 860px) { .run { grid-template-columns: 1fr; } button.go { min-height: 48px; } }
"""

PAGE_JS = """
(function () {
  var form = document.getElementById('run');
  if (form) {
    var limit = document.getElementById('limit');
    var busy = document.getElementById('busy');
    var go = document.getElementById('go');
    var syncMode = function () {
      limit.disabled = form.querySelector('input[name=mode]:checked').value === 'today';
    };
    form.addEventListener('change', syncMode);
    syncMode();
    form.addEventListener('submit', function () {
      go.disabled = true;
      go.textContent = 'Scanning\\u2026';
      busy.hidden = false;
    });
    window.addEventListener('pageshow', function () {
      busy.hidden = true;
      go.disabled = false;
      go.textContent = 'Run scan';
    });
  }
  document.querySelectorAll('.filterable').forEach(function (box) {
    var search = box.querySelector('.search');
    var rows = Array.prototype.slice.call(box.querySelectorAll('tbody tr'));
    var shown = box.querySelector('.shown');
    var chips = Array.prototype.slice.call(box.querySelectorAll('.chip'));
    var filter = 'all';
    function apply() {
      var q = search.value.trim().toLowerCase();
      var n = 0;
      rows.forEach(function (r) {
        var pass = filter === 'all' || r.dataset.cat === filter ||
          (filter === 'marked' && r.dataset.marked === 'yes') ||
          (filter === 'attach' && r.dataset.attach === 'yes');
        var hit = pass && (!q || r.dataset.text.indexOf(q) !== -1);
        r.hidden = !hit;
        if (hit) n++;
      });
      shown.textContent = n + ' shown';
    }
    chips.forEach(function (chip) {
      chip.addEventListener('click', function () {
        filter = chip.dataset.filter;
        chips.forEach(function (other) { other.setAttribute('aria-pressed', other === chip ? 'true' : 'false'); });
        apply();
      });
    });
    search.addEventListener('input', apply);
    apply();
  });
})();
"""


def as_int(value: str | None) -> int:
    try:
        return int(value or 0)
    except ValueError:
        return 0


def pretty_date(value: str) -> str:
    try:
        return friendly(datetime.date.fromisoformat(value))
    except ValueError:
        return value


def pretty_time(value: str) -> str:
    try:
        stamp = datetime.datetime.fromisoformat(value)
    except ValueError:
        return value
    return f"{friendly(stamp.date())}, {stamp.hour:02d}:{stamp.minute:02d}"


def load_runs(folder: Path) -> list[dict[str, str]]:
    return read_rows(folder / "quota_audit.csv")


def render_page(rows: list[dict[str, str]], runs: list[dict[str, str]], notice: str, ok: bool = True) -> str:
    esc = html.escape
    counts = Counter(row.get("category", "") for row in rows)
    marked = sum(1 for row in rows if row.get("mark_delete") == "yes")
    attached = [row for row in rows if row.get("attachment") == "yes"]

    def of(category: str) -> list[dict[str, str]]:
        return [row for row in rows if row.get("category") == category]

    def kind(row: dict[str, str]) -> str:
        return SUBTYPE_LABEL.get(row.get("subtype", ""), CATEGORY_NAMES.get(row.get("category", ""), "Mail"))

    def tag(row: dict[str, str]) -> str:
        return f'<span class="tag t-{esc(row.get("category", ""))}">{esc(kind(row))}</span>'

    def item_list(items: list[dict[str, str]], empty: str) -> str:
        if not items:
            return f'<p class="empty">{esc(empty)}</p>'
        lines = [
            '<li class="item">'
            + tag(row)
            + '<div class="item-main">'
            + f'<div class="subject">{esc(row.get("subject", ""))}</div>'
            + f'<div class="meta">{esc(row.get("sender", ""))} &middot; {esc(pretty_date(row.get("date", "")))}</div>'
            + "</div></li>"
            for row in items[:PANEL_CAP]
        ]
        more = ""
        if len(items) > PANEL_CAP:
            more = f'<p class="more">{len(items) - PANEL_CAP} more in the mail list below.</p>'
        return f'<ul class="list">{"".join(lines)}</ul>{more}'

    def sender_list(items: list[dict[str, str]], empty: str) -> str:
        if not items:
            return f'<p class="empty">{esc(empty)}</p>'
        groups: dict[str, list[dict[str, str]]] = defaultdict(list)
        for row in items:
            groups[row.get("email") or row.get("sender") or "unknown"].append(row)
        ranked = sorted(groups.values(), key=lambda group: (-len(group), (group[0].get("sender") or "").lower()))
        lines = []
        for group in ranked[:PANEL_CAP]:
            newest = max(group, key=lambda row: row.get("date", ""))
            flagged = sum(1 for row in group if row.get("mark_delete") == "yes")
            word = "mail" if len(group) == 1 else "mails"
            flag = f'<span class="flag">{flagged} marked</span>' if flagged else ""
            lines.append(
                '<li class="group"><div class="item-main">'
                f'<div class="subject">{esc(newest.get("sender", ""))}</div>'
                f'<div class="meta">Latest: {esc(newest.get("subject", ""))}</div>'
                f'</div>{flag}<span class="n">{len(group)} {word}</span></li>'
            )
        more = ""
        if len(ranked) > PANEL_CAP:
            more = f'<p class="more">{len(ranked) - PANEL_CAP} more senders in the mail list below.</p>'
        return f'<ul class="list">{"".join(lines)}</ul>{more}'

    def panel(title: str, sub: str, count: int, body: str) -> str:
        return (
            f'<section class="card"><h2>{esc(title)}<span class="count">{count:,}</span></h2>'
            f'<p class="sub">{esc(sub)}</p>{body}</section>'
        )

    last = runs[-1] if runs else None
    notice_html = f'<div class="notice {"ok" if ok else "err"}" role="status">{esc(notice)}</div>' if notice else ""

    stats = [
        ("Scanned", len(rows), "s-all"),
        ("Job mail", counts["interview"], "s-interview"),
        ("Events", counts["event"], "s-event"),
        ("Important", counts["important"], "s-important"),
        ("Attachments", len(attached), "s-attach"),
        ("Promotions", counts["promo"], "s-promo"),
        ("Notifications", counts["noise"], "s-noise"),
        ("Not sure", counts["review"], "s-review"),
        ("Marked for delete", marked, "s-marked"),
    ]
    stats_html = "".join(
        f'<div class="stat {cls}"><span class="stat-label">{label}</span><span class="stat-value">{value:,}</span></div>'
        for label, value, cls in stats
    )

    panels = "".join(
        [
            panel("Job mail", "Applications, interview calls, selections, rejections, offers. Totals are on the Jobs tab.",
                  counts["interview"], item_list(of("interview"), "No job mail in this scan.")),
            panel("Events and hackathons", "Hackathons, workshops, webinars, and meetups.",
                  counts["event"], item_list(of("event"), "No events in this scan.")),
            panel("Important", "Money, documents, and security alerts. Never marked for delete.",
                  counts["important"], item_list(of("important"), "Nothing important in this scan.")),
            panel("Attachments", f"Labeled {ATTACH_LABEL}. Never marked for delete.",
                  len(attached), item_list(attached, "No document attachments in this scan.")),
            panel("Promotions", "One line per sender. Marked only after three months.",
                  counts["promo"], sender_list(of("promo"), "No promotions in this scan.")),
            panel("Notifications", "One-time codes and social alerts, one line per sender.",
                  counts["noise"], sender_list(of("noise"), "No notifications in this scan.")),
        ]
    )

    if rows:
        table_rows = []
        for row in rows[:TABLE_CAP]:
            flags = ""
            if row.get("mark_delete") == "yes":
                flags += '<span class="flag">Marked</span>'
            if row.get("attachment") == "yes":
                flags += '<span class="flag f-attach">Attachment</span>'
            text = f'{row.get("sender", "")} {row.get("email", "")} {row.get("subject", "")}'.lower()
            table_rows.append(
                f'<tr data-cat="{esc(row.get("category", ""))}" data-marked="{esc(row.get("mark_delete", ""))}" '
                f'data-attach="{esc(row.get("attachment", ""))}" data-text="{esc(text)}">'
                f'<td class="nowrap">{esc(pretty_date(row.get("date", "")))}</td>'
                f"<td>{tag(row)}</td>"
                f'<td class="who"><div class="subject">{esc(row.get("sender", ""))}</div><div class="meta">{esc(row.get("email", ""))}</div></td>'
                f'<td>{esc(row.get("subject", ""))}</td>'
                f"<td>{flags}</td></tr>"
            )
        filters = [
            ("interview", "Job mail"), ("event", "Events"), ("important", "Important"),
            ("promo", "Promotions"), ("noise", "Notifications"), ("review", "Not sure"),
            ("marked", "Marked"), ("attach", "Attachments"),
        ]
        capped = ""
        if len(rows) > TABLE_CAP:
            capped = f'<p class="more">Showing the newest {TABLE_CAP:,} of {len(rows):,}. The full list is in mail_out\\mail_index.csv.</p>'
        mail_html = filter_table(
            table_rows, filters, ["Date", "Type", "Sender", "Subject", "Flags"], "Search sender or subject", capped
        )
    else:
        mail_html = '<p class="empty">No scan yet. Choose an option above and click Run scan.</p>'

    if last:
        units = as_int(last.get("units"))
        today_units = as_int(last.get("today_units"))
        peak = as_int(last.get("peak_minute"))
        alert = last.get("alert") or "No alert."
        day_width = max(today_units / DAILY_QUOTA * 100, 0.6)
        minute_share = peak / MINUTE_QUOTA * 100
        minute_width = max(min(minute_share, 100), 0.6)
        history = "".join(
            f'<tr><td class="nowrap">{esc(pretty_time(run.get("ran_at", "")))}</td>'
            f'<td>{as_int(run.get("messages_get")):,}</td><td>{as_int(run.get("units")):,}</td>'
            f'<td>{as_int(run.get("peak_minute")):,}</td><td>{esc(run.get("alert", ""))}</td></tr>'
            for run in reversed(runs[-8:])
        )
        quota_html = (
            '<div class="quota">'
            f'<div><div class="meter-label"><span>Today</span><strong>{today_units:,} / {DAILY_QUOTA:,} units '
            f'({quota_percent(today_units, DAILY_QUOTA)})</strong></div>'
            f'<div class="meter"><span style="width:{day_width:.2f}%"></span></div></div>'
            f'<div><div class="meter-label"><span>Busiest minute, last run</span><strong>{peak:,} / {MINUTE_QUOTA:,} units</strong></div>'
            f'<div class="meter{" hot" if minute_share >= 80 else ""}"><span style="width:{minute_width:.2f}%"></span></div></div>'
            "</div>"
            f'<p class="hint">Last run used {units:,} units. The daily count starts over each day. Free up to {DAILY_QUOTA:,} units a day.</p>'
            f'<div class="alert {"ok" if alert == "No alert." else "warn"}">{esc(alert)}</div>'
            '<div class="history table-wrap"><table><thead><tr><th>Run</th><th>Downloaded</th><th>Units</th>'
            f"<th>Busiest minute</th><th>Alert</th></tr></thead><tbody>{history}</tbody></table></div>"
        )
    else:
        quota_html = '<p class="empty">Quota appears here after the first run.</p>'

    return page_shell("inbox", runs, f"""
  <section class="card">
    <h2>Run a scan</h2>
    <p class="sub">Reads Gmail, sorts each message, and adds labels. It never deletes or moves mail to Trash.</p>
    <form class="run" id="run" method="post" action="/">
      <fieldset>
        <legend hidden>Which mail to read</legend>
        <label class="mode"><input type="radio" name="mode" value="limit" checked>
          <span><strong>Newest messages</strong><small>Read the most recent number you set</small></span></label>
        <label class="mode"><input type="radio" name="mode" value="today">
          <span><strong>Only today's mail</strong><small>Every message from today, no limit</small></span></label>
      </fieldset>
      <label class="limit">How many messages
        <input type="number" id="limit" name="limit" value="50" min="1" max="20000" inputmode="numeric"></label>
      <button class="go" id="go" type="submit">Run scan</button>
    </form>
    <p class="hint">Review in Gmail: <code>label:agent/markdelete</code> and <code>label:agent/attachment</code></p>
  </section>
  {notice_html}
  <div class="stats">{stats_html}</div>
  <div class="panels">{panels}</div>
  <section class="card"><h2>All mail from the last scan</h2><p class="sub">Search or filter. Everything here is still in Gmail.</p>{mail_html}</section>
  <section class="card"><h2>Gmail quota</h2><p class="sub">Counted from the calls this app makes, at Google's published cost per call.</p>{quota_html}</section>
  <div class="overlay" id="busy" hidden><div class="busy" role="status" aria-live="polite"><div class="spinner" aria-hidden="true"></div>
    <div><strong>Scanning Gmail</strong><p>Reading mail and updating labels. Nothing is deleted. Keep this tab open.</p></div></div></div>
""")


def page_shell(active: str, runs: list[dict[str, str]], body: str) -> str:
    last = runs[-1] if runs else None
    last_chip = (
        f'<span class="pill dim">Last run {html.escape(pretty_time(last.get("ran_at", "")))}</span>'
        if last
        else '<span class="pill dim">No runs yet</span>'
    )

    def tab(key: str, href: str, label: str) -> str:
        current = ' aria-current="page"' if key == active else ""
        return f'<a href="{href}"{current}>{label}</a>'

    title = "Jobs - Mail agent" if active == "jobs" else "Mail agent"
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>{PAGE_CSS}</style>
</head>
<body>
<header class="top"><div class="top-inner">
  <div class="brand"><div class="logo" aria-hidden="true">M</div>
    <div><h1>Mail agent</h1><p>Gmail summary and cleanup, running on this PC</p></div></div>
  <nav class="nav" aria-label="Pages">{tab("inbox", "/", "Inbox")}{tab("jobs", "/jobs", "Jobs")}</nav>
  <span class="pill"><span class="dot"></span>Safe mode: nothing is deleted</span>
  {last_chip}
</div></header>
<main>{body}</main>
<script>{PAGE_JS}</script>
</body>
</html>
"""


def job_counts(apps: list[dict[str, str]]) -> tuple[Counter, dict[str, Counter]]:
    totals: Counter = Counter()
    by_platform: dict[str, Counter] = defaultdict(Counter)
    for app in apps:
        totals[app["status"]] += 1
        by_platform[platform_of(app.get("email", ""))][app["status"]] += 1
    return totals, by_platform


def filter_table(rows_html: list[str], chips: list[tuple[str, str]], heads: list[str], placeholder: str, capped: str) -> str:
    chip_html = "".join(
        f'<button type="button" class="chip" data-filter="{key}" aria-pressed="{"true" if key == "all" else "false"}">{label}</button>'
        for key, label in [("all", "All"), *chips]
    )
    head_html = "".join(f"<th>{head}</th>" for head in heads)
    return (
        f'<div class="filterable"><div class="tools"><input class="search" type="search" placeholder="{placeholder}" '
        f'aria-label="{placeholder}"><div class="chips">{chip_html}</div><span class="shown"></span></div>'
        f'<div class="table-wrap"><table><thead><tr>{head_html}</tr></thead><tbody>{"".join(rows_html)}</tbody></table></div>'
        f"{capped}</div>"
    )


def render_jobs_page(rows: list[dict[str, str]], runs: list[dict[str, str]], today: datetime.date | None = None) -> str:
    esc = html.escape
    stages = dict(JOB_STAGES)
    outcome_names = dict(OUTCOMES)
    apps = application_outcomes(rows, today or datetime.date.today())
    totals, by_platform = job_counts(apps)
    mail_totals = Counter(row.get("subtype", "") for row in rows)
    empty = '<p class="empty">No job mail yet. Run a scan from the Inbox tab.</p>'

    def stat(key: str, label: str, value: int) -> str:
        return f'<div class="stat s-{key}"><span class="stat-label">{label}</span><span class="stat-value">{value:,}</span></div>'

    app_stats = stat("applied", "Applied", len(apps)) + "".join(stat(key, label, totals[key]) for key, label in OUTCOMES)
    mail_stats = "".join(stat(key, label, mail_totals[key]) for key, label in JOB_STAGES)

    if by_platform:
        ranked = sorted(by_platform.items(), key=lambda item: (-sum(item[1].values()), item[0]))
        heads = "".join(f'<th class="num">{label}</th>' for _, label in OUTCOMES)
        body = "".join(
            f'<tr><td><strong>{esc(platform)}</strong></td><td class="num"><strong>{sum(counts.values()):,}</strong></td>'
            + "".join(f'<td class="num">{counts[key]:,}</td>' for key, _ in OUTCOMES)
            + "</tr>"
            for platform, counts in ranked
        )
        platform_html = (
            f'<div class="table-wrap"><table><thead><tr><th>Applied on</th><th class="num">Applied</th>{heads}</tr></thead>'
            f"<tbody>{body}</tbody></table></div>"
        )
    else:
        platform_html = '<p class="empty">No application confirmations yet.</p>'

    if apps:
        app_rows = []
        for app in apps[:TABLE_CAP]:
            status = app["status"]
            platform = platform_of(app.get("email", ""))
            company = app.get("company") or "Unknown company"
            text = f'{company} {platform} {app.get("subject", "")}'.lower()
            reply = pretty_date(app["updated"]) if app["updated"] else "No reply"
            app_rows.append(
                f'<tr data-cat="{esc(status)}" data-text="{esc(text)}">'
                f'<td class="nowrap">{esc(pretty_date(app.get("date", "")))}</td>'
                f"<td><strong>{esc(company)}</strong></td><td>{esc(platform)}</td>"
                f'<td><span class="tag stage-{esc(status)}">{esc(outcome_names[status])}</span></td>'
                f'<td class="nowrap">{esc(reply)}</td><td>{esc(app.get("subject", ""))}</td></tr>'
            )
        capped = f'<p class="more">Showing the newest {TABLE_CAP:,} of {len(apps):,}.</p>' if len(apps) > TABLE_CAP else ""
        apps_html = filter_table(
            app_rows, list(OUTCOMES), ["Applied", "Company", "Platform", "Status", "Last reply", "Subject"],
            "Search company, platform, or subject", capped,
        )
    else:
        apps_html = empty

    if rows:
        mail_rows = []
        for row in rows[:TABLE_CAP]:
            stage = row.get("subtype", "")
            platform = platform_of(row.get("email", ""))
            text = f'{row.get("company", "")} {row.get("sender", "")} {row.get("email", "")} {row.get("subject", "")} {platform}'.lower()
            mail_rows.append(
                f'<tr data-cat="{esc(stage)}" data-text="{esc(text)}">'
                f'<td class="nowrap">{esc(pretty_date(row.get("date", "")))}</td>'
                f'<td><span class="tag stage-{esc(stage)}">{esc(stages.get(stage, stage))}</span></td>'
                f'<td>{esc(row.get("company", ""))}</td><td>{esc(platform)}</td>'
                f'<td class="who"><div class="subject">{esc(row.get("sender", ""))}</div><div class="meta">{esc(row.get("email", ""))}</div></td>'
                f'<td>{esc(row.get("subject", ""))}</td></tr>'
            )
        capped = ""
        if len(rows) > TABLE_CAP:
            capped = f'<p class="more">Showing the newest {TABLE_CAP:,} of {len(rows):,}. The full list is in mail_out\\jobs.csv.</p>'
        mail_html = filter_table(
            mail_rows, list(JOB_STAGES), ["Date", "Stage", "Company", "Platform", "Sender", "Subject"],
            "Search company, platform, or subject", capped,
        )
    else:
        mail_html = empty

    return page_shell("jobs", runs, f"""
  <section class="card">
    <h2>Applications</h2>
    <p class="sub">Each application confirmation counts once, by its Gmail id, so running again never adds it twice.
      It is linked to later replies from the same company. No reply after {GHOST_DAYS} days means Ghosted;
      a later rejection or selection moves it out of Ghosted on the next scan.</p>
    <div class="stats">{app_stats}</div>
  </section>
  <section class="card">
    <h2>Job emails received</h2>
    <p class="sub">Every job email ever downloaded, each counted once. Includes replies for applications that had no
      confirmation email, so these can be higher than the numbers above.</p>
    <div class="stats">{mail_stats}</div>
  </section>
  <section class="card"><h2>By platform</h2>
    <p class="sub">Where you applied, from the confirmation email, and what happened to those applications.</p>{platform_html}</section>
  <section class="card"><h2>Every application</h2><p class="sub">Newest first. Filter by status.</p>{apps_html}</section>
  <section class="card"><h2>All job mail</h2><p class="sub">Newest first. Search or filter by stage.</p>{mail_html}</section>
""")


def render_saved_page(folder: Path, notice: str, ok: bool = True) -> str:
    page = render_page(load_index(folder), load_runs(folder), notice, ok)
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "mail.html").write_text(page, encoding="utf-8")
    return page


def render_saved_jobs(folder: Path) -> str:
    page = render_jobs_page(load_jobs(folder), load_runs(folder))
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "jobs.html").write_text(page, encoding="utf-8")
    return page


def run_scan(out: Path, credentials: Path, token: Path, limit: int, today_only: bool, report_only: bool, daily: bool = False) -> int:
    USAGE.clear()
    print("Connecting to Gmail. Nothing will be deleted.", flush=True)
    service = connect(credentials, token, interactive=not daily)
    today = datetime.date.today()
    now = datetime.datetime.now()
    query = f"{QUERY} newer_than:7d" if daily else mailbox_query(today_only, today)
    print("Listing mail.", flush=True)
    ids = list_ids(service, 0 if today_only else limit, query)
    print(f"Mailbox list has {len(ids)} messages.", flush=True)
    if report_only:
        mark_id = find_label(service, MARK_LABEL)
        attach_id = find_label(service, ATTACH_LABEL)
    else:
        mark_id = ensure_label(service, MARK_LABEL)
        attach_id = ensure_label(service, ATTACH_LABEL)

    conn = open_db(out / "mail_cache.db")
    cached = list(conn.execute("SELECT id, attachment FROM msgs"))
    known = {row["id"] for row in cached}
    stale = {row["id"] for row in cached if row["attachment"] is None}
    missing = [mid for mid in ids if mid not in known or mid in stale]
    if missing:
        minutes = len(missing) * METHOD_UNITS["messages.get"] // (MINUTE_QUOTA * 9 // 10) + 1
        print(f"Downloading {len(missing)} new messages. About {minutes} minutes; progress is saved as it goes.", flush=True)
        fetch_messages(service, conn, missing, mark_id, attach_id)
    else:
        print("No new messages to download.", flush=True)

    mails = load_mails(conn, ids, today)
    added = removed = attach_added = attach_removed = 0
    if not report_only:
        added, removed = sync_label(
            service, mark_id, conn, mails,
            lambda mail: mail.verdict.mark_delete, lambda mail: mail.marked,
            "marked", MARK_LABEL,
        )
        attach_added, attach_removed = sync_label(
            service, attach_id, conn, mails,
            lambda mail: mail.attachment, lambda mail: mail.attachment_labeled,
            "attachment_labeled", ATTACH_LABEL,
        )
        print(f"Label {MARK_LABEL}: added {added}, removed {removed}. Deleted 0.", flush=True)
        print(f"Label {ATTACH_LABEL}: added {attach_added}, removed {attach_removed}.", flush=True)
    write_outputs(out, mails)
    everything = load_mails(conn, [row["id"] for row in conn.execute("SELECT id FROM msgs")], today)
    write_outputs(out, [mail for mail in everything if mail.verdict.category == "interview"], "jobs.csv")
    quota = record_quota(out, USAGE, now)
    print(quota, flush=True)
    render_saved_page(out, f"Scan finished. {len(mails)} messages checked. Nothing was deleted.")
    render_saved_jobs(out)
    marked = sum(1 for mail in mails if mail.verdict.mark_delete)
    print(f"Scanned {len(mails)}. Marked for delete {marked}. Deleted 0.", flush=True)
    if daily:
        fresh = set(missing)
        notify(*daily_message([mail for mail in mails if mail.id in fresh]))
    print((out / "mail.html").resolve(), flush=True)
    print((out / "mail_index.csv").resolve(), flush=True)
    return len(mails)


def serve_page(out: Path, credentials: Path, token: Path) -> None:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args) -> None:
            print(f"  page {args[0]}", flush=True)

        def _send(self, body: str) -> None:
            data = body.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _back(self, notice: str, ok: bool) -> None:
            flash[:] = [notice, ok]
            self.send_response(303)
            self.send_header("Location", "/")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def do_GET(self) -> None:
            if self.path == "/jobs":
                self._send(render_saved_jobs(out))
                return
            if self.path != "/":
                self.send_error(404)
                return
            notice, ok = flash or ["", True]
            flash.clear()
            self._send(render_saved_page(out, notice, ok))

        def do_POST(self) -> None:
            size = int(self.headers.get("Content-Length", "0") or 0)
            form = urllib.parse.parse_qs(self.rfile.read(size).decode("utf-8", "replace"))
            mode = (form.get("mode") or ["limit"])[0]
            raw_limit = (form.get("limit") or ["10"])[0]
            try:
                limit = int(raw_limit)
            except ValueError:
                self._back("How many messages must be a number.", False)
                return
            if mode != "today" and limit < 1:
                self._back("How many messages must be at least 1.", False)
                return
            if not SCAN_LOCK.acquire(blocking=False):
                self._back("A scan is already running. Wait for it to finish.", False)
                return
            try:
                count = run_scan(out, credentials, token, limit, mode == "today", False)
                what = "today's mail" if mode == "today" else f"the newest {limit:,}"
                self._back(f"Scan finished: {count:,} messages from {what}. Nothing was deleted.", True)
            except SystemExit as err:
                self._back(f"Scan stopped. {err}", False)
            finally:
                SCAN_LOCK.release()

    flash: list = []

    try:
        server = ThreadingHTTPServer(("127.0.0.1", PAGE_PORT), Handler)
    except OSError as err:
        raise SystemExit(f"Could not open the page on port {PAGE_PORT}: {err}") from err
    url = f"http://127.0.0.1:{PAGE_PORT}"
    print(f"Page: {url}", flush=True)
    print("Leave this window open. Nothing is deleted.", flush=True)
    webbrowser.open(url)
    server.serve_forever()


def main(argv: list[str] | None = None) -> int:
    self_check()
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true", help="run the built-in checks and exit")
    parser.add_argument("--limit", type=int, default=0, help="only the newest N messages, for a first look")
    parser.add_argument("--today", action="store_true", help="only today's mail, with no limit")
    parser.add_argument("--daily", action="store_true", help="for Task Scheduler: last 7 days, only new mail is downloaded and notified, log to file")
    parser.add_argument("--serve", action="store_true", help="open the local page")
    parser.add_argument("--report-only", action="store_true", help="write the files and do not change Gmail labels")
    parser.add_argument("--out", type=Path, default=HERE / "mail_out", help="folder for the brief and the index")
    parser.add_argument("--credentials", type=Path, default=HERE / "credentials.json")
    parser.add_argument("--token", type=Path, default=HERE / "token.json")
    args = parser.parse_args(argv)
    if args.check:
        print("Checks passed.")
        return 0
    if args.limit < 0:
        raise SystemExit("--limit must be 0 or more")
    if args.serve:
        serve_page(args.out, args.credentials, args.token)
        return 0
    if args.daily:
        args.out.mkdir(parents=True, exist_ok=True)
        sys.stdout = sys.stderr = (args.out / "daily.log").open("a", encoding="utf-8")
        print(f"\n=== {datetime.datetime.now().isoformat(timespec='seconds')} ===", flush=True)
        try:
            run_scan(args.out, args.credentials, args.token, 0, True, args.report_only, daily=True)
        except (SystemExit, Exception) as err:
            notify("Mail agent: daily scan failed", str(err)[:250])
            return 1
        return 0
    run_scan(args.out, args.credentials, args.token, args.limit, args.today, args.report_only)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("Stopped.", file=sys.stderr)
        raise SystemExit(1)
