#!/usr/bin/env python3
"""Sort a LinkedIn connections export into categories.

Download the file from LinkedIn (does not log in or scrape):
  Me → Settings & Privacy → Data privacy → Get a copy of your data
  → leave "Download larger data archive" selected → Request archive
  When the zip arrives, unzip it and pass Connections.csv to this script.

First matching category wins:
  student_no_experience  title looks like a student and not a job
  same_company           company or title mentions --company
  same_college           company, title, or an education column mentions --college
  it_domain              title looks like software / IT
  non_it                 title looks like a non-IT field
  unknown                not enough text to tell

The connections file has the current company and position only. College is
found when that name shows up in those fields (students often list the college
as the company). Past jobs are not in this export.
"""

from __future__ import annotations

import argparse
import csv
import re
import sys
import tempfile
from collections import Counter
from pathlib import Path

CATEGORIES = (
    "student_no_experience",
    "same_company",
    "same_college",
    "it_domain",
    "non_it",
    "unknown",
)

# Current title only. "b.tech" alone is not a student signal: alumni put it
# next to a job title.
STUDENT = (
    "student",
    "fresher",
    "undergraduate",
    "undergrad",
    "pursuing",
    "final year",
    "pre-final",
    "prefinal",
    "graduate student",
)

# Disqualifies the student bucket. "intern" counts as experience.
EXPERIENCE = (
    "intern",
    "internship",
    "trainee",
    "apprentice",
    "engineer",
    "developer",
    "programmer",
    "analyst",
    "manager",
    "consultant",
    "associate",
    "executive",
    "officer",
    "founder",
    "co-founder",
    "cofounder",
    "ceo",
    "cto",
    "director",
    "designer",
    "architect",
    "administrator",
    "recruiter",
    "teacher",
    "professor",
    "lecturer",
    "lead",
)

# Checked before non-IT phrases. Specific on purpose: bare "engineer" is not IT.
IT = (
    "software",
    "developer",
    "programmer",
    "sde",
    "swe",
    "devops",
    "devsecops",
    "sre",
    "site reliability",
    "data scientist",
    "data science",
    "data engineer",
    "data analyst",
    "machine learning",
    "artificial intelligence",
    "deep learning",
    "computer vision",
    "full stack",
    "fullstack",
    "full-stack",
    "frontend",
    "front-end",
    "front end",
    "backend",
    "back-end",
    "back end",
    "web developer",
    "web development",
    "android",
    "ios developer",
    "qa engineer",
    "test engineer",
    "automation engineer",
    "cybersecurity",
    "cyber security",
    "information security",
    "infosec",
    "cloud engineer",
    "network engineer",
    "technical support",
    "it support",
    "information technology",
    "system engineer",
    "systems engineer",
    "product manager",
    "scrum master",
    "ui/ux",
    "ux designer",
    "ui designer",
    "database",
    "software architect",
    "solution architect",
    "technical architect",
    "tech lead",
    "technical lead",
    "engineering manager",
    "application developer",
    "app developer",
    "firmware",
    "embedded",
    "mlops",
    "business analyst",
    "technology analyst",
    "it analyst",
    "salesforce",
    "power bi",
    "tableau",
    "python",
    "java",
    "javascript",
    ".net",
    "dotnet",
    "react",
    "node.js",
    "nodejs",
)

NON_IT = (
    "human resource",
    "human resources",
    "hr",
    "recruiter",
    "talent acquisition",
    "sales",
    "marketing",
    "accountant",
    "chartered accountant",
    "finance",
    "banker",
    "banking",
    "teacher",
    "professor",
    "lecturer",
    "doctor",
    "nurse",
    "lawyer",
    "advocate",
    "civil engineer",
    "mechanical engineer",
    "chemical engineer",
    "electrical engineer",
    "electronics engineer",
    "automobile",
    "pharmacist",
    "hotel",
    "supply chain",
    "logistics",
    "operations manager",
    "store manager",
    "content writer",
    "journalist",
    "photographer",
    "graphic designer",
    "interior designer",
    "fashion",
    "architect",
)

SHORT = {"sde", "swe", "sre", "qa", "hr", "ai", "ml", "ios", "ceo", "cto"}


def has_phrase(text: str, phrase: str) -> bool:
    phrase = phrase.lower()
    if " " not in phrase and (len(phrase) <= 3 or phrase in SHORT):
        return re.search(rf"\b{re.escape(phrase)}\b", text) is not None
    return phrase in text


def has_any(text: str, phrases: tuple[str, ...]) -> bool:
    return any(has_phrase(text, phrase) for phrase in phrases)


def contains_name(text: str, name: str) -> bool:
    name = " ".join(name.lower().split())
    if not name:
        return False
    # Short names ("MIT", "COEP") must match a whole word.
    if len(name) <= 4:
        return re.search(rf"\b{re.escape(name)}\b", text) is not None
    return name in text


def blob(*parts: str) -> str:
    return " ".join(part.strip().lower() for part in parts if part and part.strip())


def classify(position: str, company: str, education: str, companies: list[str], colleges: list[str]) -> str:
    title = blob(position)
    org = blob(company)
    school = blob(education)
    all_text = blob(title, org, school)

    if has_any(title, STUDENT) and not has_any(title, EXPERIENCE):
        return "student_no_experience"
    if any(contains_name(org, name) or contains_name(title, name) for name in companies):
        return "same_company"
    if any(contains_name(all_text, name) for name in colleges):
        return "same_college"
    # ponytail: headline keywords only; a mixed headline ("sales, ex-developer")
    # lands in it_domain. Upgrade path: review the unknown file by hand.
    if has_any(all_text, IT):
        return "it_domain"
    if has_any(all_text, NON_IT):
        return "non_it"
    return "unknown"


def education_text(row: dict[str, str]) -> str:
    parts = []
    for key, value in row.items():
        if key and value and re.search(r"educat|school|college|university", key, re.I):
            parts.append(value)
    return " ".join(parts)


def read_connections(path: Path) -> list[dict[str, str]]:
    raw = path.read_text(encoding="utf-8-sig")
    lines = raw.splitlines()
    start = 0
    for index, line in enumerate(lines):
        if "first name" in line.lower() and "company" in line.lower():
            start = index
            break
    else:
        raise SystemExit(f"{path} has no First Name / Company header. Export Connections.csv from LinkedIn.")
    return list(csv.DictReader(lines[start:]))


def field(row: dict[str, str], *names: str) -> str:
    lowered = {((key or "").strip().lower()): (value or "") for key, value in row.items()}
    for name in names:
        if name in lowered and lowered[name].strip():
            return lowered[name].strip()
    return ""


def write_category(path: Path, fieldnames: list[str], rows: list[dict[str, str]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def self_check() -> None:
    college = ["COEP Technological University"]
    company = ["Acme Tech"]

    def kind(position: str, org: str = "", education: str = "") -> str:
        return classify(position, org, education, company, college)

    assert kind("Student", "COEP Technological University") == "student_no_experience"
    assert kind("B.Tech Student") == "student_no_experience"
    assert kind("Software Intern", "COEP Technological University") == "same_college"
    assert kind("Software Engineer", "Acme Tech Pvt Ltd") == "same_company"
    assert kind("Data Engineer at Acme Tech") == "same_company"
    assert kind("Mechanical Engineer", "Alumni, COEP Technological University") == "same_college"
    assert kind("Data Engineer", "Other Corp") == "it_domain"
    assert kind("Sales Manager", "Other Corp") == "non_it"
    assert kind("HR Executive", "Other Corp") == "non_it"
    assert kind("Civil Engineer", "BuildCo") == "non_it"
    assert kind("", "") == "unknown"
    assert kind("Solution Architect", "Other Corp") == "it_domain"
    assert contains_name("studied at mit college", "mit")
    assert not contains_name("submitted the form", "mit")

    with tempfile.TemporaryDirectory() as folder:
        source = Path(folder) / "Connections.csv"
        source.write_text(
            "Notes:\n"
            "\"Some emails are hidden\"\n"
            "\n"
            "First Name,Last Name,URL,Email Address,Company,Position,Connected On\n"
            "Ava,Shah,https://linkedin.com/in/ava,,COEP Technological University,Student,01 Jan 2024\n"
            "Ben,Roy,https://linkedin.com/in/ben,,Acme Tech,Software Engineer,02 Jan 2024\n"
            "Cia,Das,https://linkedin.com/in/cia,,Other Corp,Sales Manager,03 Jan 2024\n",
            encoding="utf-8",
        )
        got = {
            field(row, "first name"): classify(
                field(row, "position"),
                field(row, "company"),
                "",
                company,
                college,
            )
            for row in read_connections(source)
        }
        assert got == {
            "Ava": "student_no_experience",
            "Ben": "same_company",
            "Cia": "non_it",
        }


def main(argv: list[str] | None = None) -> int:
    self_check()
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("csv_path", nargs="?", type=Path, help="LinkedIn Connections.csv")
    parser.add_argument("--company", action="append", default=[], help="your company; repeat for more than one")
    parser.add_argument("--college", action="append", default=[], help="your college; repeat for more than one")
    parser.add_argument("--out", type=Path, default=Path("categorized"), help="output folder (default: categorized)")
    args = parser.parse_args(argv)

    if args.csv_path is None:
        print("Passed the built-in checks. Give a Connections.csv to sort real people.", file=sys.stderr)
        print("Example: python filter_linkedin.py Connections.csv --company \"Acme\" --college \"COEP\"", file=sys.stderr)
        return 0
    if not args.csv_path.is_file():
        raise SystemExit(f"File not found: {args.csv_path}")
    if not args.company:
        print("No --company given, so nobody is filed under same_company.", file=sys.stderr)
    if not args.college:
        print("No --college given, so nobody is filed under same_college.", file=sys.stderr)

    rows = read_connections(args.csv_path)
    buckets: dict[str, list[dict[str, str]]] = {name: [] for name in CATEGORIES}
    for row in rows:
        position = field(row, "position", "title", "headline")
        company = field(row, "company", "organization")
        category = classify(position, company, education_text(row), args.company, args.college)
        labeled = dict(row)
        labeled["Category"] = category
        buckets[category].append(labeled)

    args.out.mkdir(parents=True, exist_ok=True)
    counts = Counter()
    fieldnames: list[str] = []
    for row in rows:
        for key in row:
            if key and key not in fieldnames:
                fieldnames.append(key)
    fieldnames.append("Category")
    for category in CATEGORIES:
        write_category(args.out / f"{category}.csv", fieldnames, buckets[category])
        counts[category] = len(buckets[category])

    print(f"Read {len(rows)} connections from {args.csv_path}")
    for category in CATEGORIES:
        print(f"  {category}: {counts[category]}")
    print(f"Wrote one CSV per category in {args.out.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
